#!/usr/bin/env python3
"""
Input Validation and Security Module
Author: ibrahimsql
Description: Secure input validation and sanitization operations
"""

import re
import html
import urllib.parse
import ipaddress
from typing import Optional, List, Dict, Any
import bleach
from pathlib import Path
import base64
import json

class InputValidator:
    """Input validation and security class"""
    
    # Safe characters
    SAFE_FILENAME_CHARS = re.compile(r'^[a-zA-Z0-9._-]+$')
    SAFE_USERNAME_CHARS = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
    
    # Dangerous SQL characters
    SQL_DANGEROUS_CHARS = ["'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_', 'UNION', 'SELECT', 'DROP', 'DELETE', 'INSERT', 'UPDATE']
    
    # XSS tehlikeli taglar
    DANGEROUS_TAGS = ['script', 'iframe', 'object', 'embed', 'form', 'input', 'textarea', 'button', 'select', 'option']
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Email format validation"""
        if not email or len(email) > 254:
            return False
        
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """Username validation"""
        if not username:
            return False
        
        # Only alphanumeric characters and underscore
        return bool(InputValidator.SAFE_USERNAME_CHARS.match(username))
    
    @staticmethod
    def validate_password_strength(password: str) -> Dict[str, Any]:
        """Password strength check"""
        result = {
            'is_strong': False,
            'score': 0,
            'issues': []
        }
        
        if len(password) < 8:
            result['issues'].append('Password must be at least 8 characters long')
        else:
            result['score'] += 1
        
        if not re.search(r'[a-z]', password):
            result['issues'].append('Password must contain lowercase letters')
        else:
            result['score'] += 1
        
        if not re.search(r'[A-Z]', password):
            result['issues'].append('Password must contain uppercase letters')
        else:
            result['score'] += 1
        
        if not re.search(r'\d', password):
            result['issues'].append('Password must contain numbers')
        else:
            result['score'] += 1
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            result['issues'].append('Password must contain special characters')
        else:
            result['score'] += 1
        
        # Common passwords check
        common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
        if password.lower() in common_passwords:
            result['issues'].append('Password is too common')
            result['score'] -= 2
        
        result['is_strong'] = result['score'] >= 4 and len(result['issues']) == 0
        return result
    
    @staticmethod
    def sanitize_html(input_str: str, allowed_tags: List[str] = None) -> str:
        """HTML character cleaning"""
        if allowed_tags is None:
            allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'p', 'br']
        
        # Safe HTML cleaning using Bleach
        cleaned = bleach.clean(
            input_str,
            tags=allowed_tags,
            attributes={},
            strip=True
        )
        
        return cleaned
    
    @staticmethod
    def escape_html(input_str: str) -> str:
        """HTML character escaping"""
        return html.escape(input_str, quote=True)
    
    @staticmethod
    def validate_file_path(file_path: str, allowed_extensions: List[str] = None) -> bool:
        """File path validation (Path Traversal protection)"""
        if not file_path:
            return False
        
        # Block path traversal attacks
        if '..' in file_path or file_path.startswith('/') or '\\' in file_path:
            return False
        
        # Null byte injection
        if '\x00' in file_path:
            return False
        
        # Filename check
        filename = Path(file_path).name
        if not InputValidator.SAFE_FILENAME_CHARS.match(filename):
            return False
        
        # Extension check
        if allowed_extensions:
            file_extension = Path(file_path).suffix.lower()
            if file_extension not in allowed_extensions:
                return False
        
        return True
    
    @staticmethod
    def validate_sql_input(input_str: str) -> str:
        """Input cleaning for SQL injection protection"""
        if not input_str:
            return ''
        
        # Tehlikeli karakterleri kaldır
        cleaned = input_str
        for char in InputValidator.SQL_DANGEROUS_CHARS:
            cleaned = cleaned.replace(char, '')
        
        return cleaned.strip()
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """URL format validation"""
        if not url:
            return False
        
        # Basic URL pattern
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'  # domain...
            r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # host...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        return bool(url_pattern.match(url))
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """IP adresi doğrulama"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_port(port: str) -> bool:
        """Port numarası doğrulama"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except ValueError:
            return False
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Dosya adını güvenli hale getirme"""
        # Tehlikeli karakterleri kaldır
        sanitized = re.sub(r'[<>:"/\\|?*]', '', filename)
        
        # Windows reserved names
        reserved_names = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 
                         'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 
                         'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9']
        
        name_without_ext = Path(sanitized).stem.upper()
        if name_without_ext in reserved_names:
            sanitized = f"file_{sanitized}"
        
        # Maksimum uzunluk
        if len(sanitized) > 255:
            name = Path(sanitized).stem[:200]
            ext = Path(sanitized).suffix
            sanitized = f"{name}{ext}"
        
        return sanitized
    
    @staticmethod
    def validate_json(json_str: str) -> bool:
        """JSON format doğrulama"""
        try:
            json.loads(json_str)
            return True
        except (json.JSONDecodeError, TypeError):
            return False
    
    @staticmethod
    def validate_base64(data: str) -> bool:
        """Base64 format doğrulama"""
        try:
            base64.b64decode(data, validate=True)
            return True
        except Exception:
            return False
    
    @staticmethod
    def sanitize_command_injection(input_str: str) -> str:
        """Command injection saldırılarına karşı koruma"""
        if not input_str:
            return ''
        
        # Tehlikeli karakterleri kaldır
        dangerous_chars = ['&', '|', ';', '$', '`', '>', '<', '(', ')', '{', '}', '[', ']']
        
        sanitized = input_str
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        return sanitized.strip()
    
    @staticmethod
    def validate_credit_card(card_number: str) -> Dict[str, Any]:
        """Kredi kartı numarası doğrulama (Luhn algoritması)"""
        # Sadece rakamları al
        digits = re.sub(r'\D', '', card_number)
        
        result = {
            'is_valid': False,
            'card_type': 'Unknown',
            'masked_number': ''
        }
        
        if len(digits) < 13 or len(digits) > 19:
            return result
        
        # Luhn algoritması
        def luhn_check(card_num):
            def digits_of(n):
                return [int(d) for d in str(n)]
            
            digits = digits_of(card_num)
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d*2))
            return checksum % 10 == 0
        
        result['is_valid'] = luhn_check(digits)
        
        # Kart türü tespiti
        if digits.startswith('4'):
            result['card_type'] = 'Visa'
        elif digits.startswith(('51', '52', '53', '54', '55')):
            result['card_type'] = 'MasterCard'
        elif digits.startswith(('34', '37')):
            result['card_type'] = 'American Express'
        elif digits.startswith('6011'):
            result['card_type'] = 'Discover'
        
        # Maskelenmiş numara
        if len(digits) >= 4:
            result['masked_number'] = '*' * (len(digits) - 4) + digits[-4:]
        
        return result
    
    @staticmethod
    def validate_phone_number(phone: str, country_code: str = 'TR') -> bool:
        """Telefon numarası doğrulama"""
        # Sadece rakamları al
        digits = re.sub(r'\D', '', phone)
        
        patterns = {
            'TR': r'^(90)?5\d{9}$',  # Türkiye
            'US': r'^(1)?[2-9]\d{2}[2-9]\d{2}\d{4}$',  # ABD
            'UK': r'^(44)?[1-9]\d{8,9}$'  # İngiltere
        }
        
        pattern = patterns.get(country_code, r'^\d{10,15}$')
        return bool(re.match(pattern, digits))
    
    @staticmethod
    def rate_limit_check(identifier: str, max_requests: int = 100, time_window: int = 3600) -> bool:
        """Rate limiting kontrolü (basit implementasyon)"""
        import time
        
        # Bu gerçek uygulamada Redis veya veritabanı ile yapılmalı
        # Şimdilik basit bir dictionary kullanıyoruz
        if not hasattr(InputValidator, '_rate_limit_store'):
            InputValidator._rate_limit_store = {}
        
        current_time = time.time()
        
        if identifier not in InputValidator._rate_limit_store:
            InputValidator._rate_limit_store[identifier] = []
        
        # Eski kayıtları temizle
        InputValidator._rate_limit_store[identifier] = [
            timestamp for timestamp in InputValidator._rate_limit_store[identifier]
            if current_time - timestamp < time_window
        ]
        
        # Limit kontrolü
        if len(InputValidator._rate_limit_store[identifier]) >= max_requests:
            return False
        
        # Yeni isteği kaydet
        InputValidator._rate_limit_store[identifier].append(current_time)
        return True

class SecurityHeaders:
    """Güvenlik başlıkları yönetimi"""
    
    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """Güvenlik başlıklarını al"""
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }

# Kullanım örnekleri
if __name__ == "__main__":
    validator = InputValidator()
    
    # Email doğrulama
    email = "test@example.com"
    print(f"Email valid: {validator.validate_email(email)}")
    
    # Şifre güçlülük kontrolü
    password = "MyStr0ng!Pass"
    strength = validator.validate_password_strength(password)
    print(f"Password strength: {strength}")
    
    # HTML sanitization
    html_input = "<script>alert('xss')</script><p>Safe content</p>"
    sanitized = validator.sanitize_html(html_input)
    print(f"Sanitized HTML: {sanitized}")
    
    # Dosya yolu doğrulama
    file_path = "document.pdf"
    is_safe = validator.validate_file_path(file_path, ['.pdf', '.doc', '.txt'])
    print(f"File path safe: {is_safe}")
    
    # URL doğrulama
    url = "https://example.com/path"
    print(f"URL valid: {validator.validate_url(url)}")
    
    # IP adresi doğrulama
    ip = "192.168.1.1"
    print(f"IP valid: {validator.validate_ip_address(ip)}")
    
    # Kredi kartı doğrulama
    card = "4532015112830366"
    card_info = validator.validate_credit_card(card)
    print(f"Credit card info: {card_info}")
    
    # Güvenlik başlıkları
    headers = SecurityHeaders.get_security_headers()
    print(f"Security headers: {headers}")