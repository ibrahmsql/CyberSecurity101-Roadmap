#!/usr/bin/env python3
"""
Basic Security Examples
Author: ibrahimsql
Description: Basic cybersecurity concepts and examples
"""

import struct
import re
import hashlib
import secrets
import urllib.parse
from typing import List, Dict, Optional

class BasicSecurityExamples:
    """Basic security examples class"""
    
    @staticmethod
    def buffer_overflow_example() -> bytes:
        """Buffer overflow exploit example (educational purpose only)"""
        # Buffer Overflow Exploit
        buffer = b"A" * 1024
        ret_addr = struct.pack("<I", 0x41414141)
        payload = buffer + ret_addr
        
        print("⚠️  Buffer Overflow Payload Generated (Educational Purpose Only)")
        print(f"Buffer size: {len(buffer)} bytes")
        print(f"Return address: 0x41414141")
        print(f"Total payload size: {len(payload)} bytes")
        
        return payload
    
    @staticmethod
    def sql_injection_examples() -> List[str]:
        """SQL injection payload examples (educational purpose only)"""
        payloads = [
            "1' OR '1'='1' --",
            "'; DROP TABLE users; --",
            "1' UNION SELECT username, password FROM users --",
            "admin'--",
            "' OR 1=1#",
            "1' AND (SELECT COUNT(*) FROM users) > 0 --"
        ]
        
        print("⚠️  SQL Injection Payloads (Educational Purpose Only):")
        for i, payload in enumerate(payloads, 1):
            print(f"{i}. {payload}")
            
        return payloads
    
    @staticmethod
    def validate_username_secure(username: str) -> bool:
        """Secure username validation (Whitelist approach)"""
        pattern = r'^[a-zA-Z0-9_]{3,20}$'
        return re.match(pattern, username) is not None
    
    @staticmethod
    def validate_username_insecure(username: str) -> bool:
        """Insecure username validation (Blacklist approach)"""
        forbidden = ['<', '>', '&', '"', "'"]
        return not any(char in username for char in forbidden)
    
    @staticmethod
    def demonstrate_validation_difference():
        """Demonstrate the difference between Whitelist vs Blacklist validation"""
        test_usernames = [
            "admin",           # Valid
            "user123",         # Valid
            "test_user",       # Valid
            "<script>",        # Invalid
            "user@domain",     # Passes blacklist, fails whitelist
            "user name",       # Passes blacklist, fails whitelist
            "user#123",        # Passes blacklist, fails whitelist
            "a",               # Too short
            "verylongusernamethatexceedslimit"  # Too long
        ]
        
        print("\n🔍 Username Validation Comparison:")
        print("Username\t\t\tWhitelist\tBlacklist")
        print("-" * 50)
        
        for username in test_usernames:
            whitelist_result = BasicSecurityExamples.validate_username_secure(username)
            blacklist_result = BasicSecurityExamples.validate_username_insecure(username)
            
            print(f"{username:<20}\t{whitelist_result}\t\t{blacklist_result}")
    
    @staticmethod
    def xss_examples() -> Dict[str, str]:
        """XSS attack examples and protections"""
        xss_payloads = {
            "Basic Script": "<script>alert('XSS')</script>",
            "Image XSS": "<img src=x onerror=alert('XSS')>",
            "Event Handler": "<div onmouseover=alert('XSS')>Hover me</div>",
            "JavaScript URL": "<a href=javascript:alert('XSS')>Click me</a>",
            "SVG XSS": "<svg onload=alert('XSS')></svg>",
            "Body XSS": "<body onload=alert('XSS')>"
        }
        
        print("⚠️  XSS Payloads (Educational Purpose Only):")
        for name, payload in xss_payloads.items():
            print(f"{name}: {payload}")
            
        return xss_payloads
    
    @staticmethod
    def html_encode(text: str) -> str:
        """HTML encoding (XSS protection)"""
        html_chars = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;'
        }
        
        for char, encoded in html_chars.items():
            text = text.replace(char, encoded)
            
        return text
    
    @staticmethod
    def url_encode(text: str) -> str:
        """URL encoding"""
        return urllib.parse.quote(text)
    
    @staticmethod
    def demonstrate_encoding():
        """Demonstrate encoding examples"""
        malicious_input = "<script>alert('XSS')</script>"
        
        print("\n🛡️  Encoding Examples:")
        print(f"Original: {malicious_input}")
        print(f"HTML Encoded: {BasicSecurityExamples.html_encode(malicious_input)}")
        print(f"URL Encoded: {BasicSecurityExamples.url_encode(malicious_input)}")
    
    @staticmethod
    def password_security_examples():
        """Password security examples"""
        weak_passwords = [
            "123456",
            "password",
            "admin",
            "qwerty",
            "letmein"
        ]
        
        strong_passwords = [
            "MyStr0ng!P@ssw0rd",
            "C0mpl3x#P@ss2023",
            "S3cur3$P@ssw0rd!",
            "Ungu3ss@bl3!2023",
            "R@nd0m#Str0ng!P@ss"
        ]
        
        print("\n🔐 Password Security Examples:")
        print("\nWeak Passwords (DON'T USE):")
        for pwd in weak_passwords:
            print(f"❌ {pwd}")
            
        print("\nStrong Passwords:")
        for pwd in strong_passwords:
            print(f"✅ {pwd}")
    
    @staticmethod
    def hash_password_examples():
        """Password hashing examples"""
        password = "MySecretPassword123!"
        
        # MD5 (Insecure)
        md5_hash = hashlib.md5(password.encode()).hexdigest()
        
        # SHA1 (Insecure)
        sha1_hash = hashlib.sha1(password.encode()).hexdigest()
        
        # SHA256 (Better but insufficient without salt)
        sha256_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # SHA256 with Salt (Recommended)
        salt = secrets.token_hex(16)
        salted_password = password + salt
        sha256_salted = hashlib.sha256(salted_password.encode()).hexdigest()
        
        print("\n🔒 Password Hashing Examples:")
        print(f"Original Password: {password}")
        print(f"MD5 (Insecure): {md5_hash}")
        print(f"SHA1 (Insecure): {sha1_hash}")
        print(f"SHA256 (Better): {sha256_hash}")
        print(f"Salt: {salt}")
        print(f"SHA256 + Salt (Recommended): {sha256_salted}")
    
    @staticmethod
    def phishing_indicators() -> List[str]:
        """Phishing attack indicators"""
        indicators = [
            "Messages requiring urgent action",
            "Suspicious sender addresses (typosquatting)",
            "Poor spelling and grammar errors",
            "Suspicious links and URLs",
            "Personal information requests",
            "Threatening language usage",
            "Unexpected attachments",
            "Too good to be true offers"
        ]
        
        print("\n🎣 Phishing Attack Indicators:")
        for i, indicator in enumerate(indicators, 1):
            print(f"{i}. {indicator}")
            
        return indicators
    
    @staticmethod
    def analyze_suspicious_email(email_content: str) -> Dict[str, any]:
        """Suspicious email analysis"""
        suspicious_keywords = [
            "urgent", "immediately", "now", "last chance", "free",
            "you won", "congratulations", "verification", "account will be closed",
            "security", "suspicious activity", "click here", "act now"
        ]
        
        suspicious_domains = [
            ".tk", ".ml", ".ga", ".cf", "bit.ly", "tinyurl.com"
        ]
        
        analysis = {
            "risk_score": 0,
            "suspicious_keywords": [],
            "suspicious_domains": [],
            "risk_level": "LOW"
        }
        
        email_lower = email_content.lower()
        
        # Suspicious keyword check
        for keyword in suspicious_keywords:
            if keyword in email_lower:
                analysis["suspicious_keywords"].append(keyword)
                analysis["risk_score"] += 10
        
        # Suspicious domain check
        for domain in suspicious_domains:
            if domain in email_lower:
                analysis["suspicious_domains"].append(domain)
                analysis["risk_score"] += 15
        
        # Risk level determination
        if analysis["risk_score"] >= 50:
            analysis["risk_level"] = "HIGH"
        elif analysis["risk_score"] >= 25:
            analysis["risk_level"] = "MEDIUM"
        
        return analysis
    
    @staticmethod
    def network_security_basics():
        """Network security basics"""
        concepts = {
            "Firewall": "Security system that controls network traffic",
            "IDS": "Intrusion Detection System - Attack detection system",
            "IPS": "Intrusion Prevention System - Attack prevention system",
            "VPN": "Virtual Private Network - Secure network connection",
            "DMZ": "Demilitarized Zone - Buffer zone",
            "NAT": "Network Address Translation - IP address translation",
            "VLAN": "Virtual Local Area Network - Virtual network segment",
            "SSL/TLS": "Secure Socket Layer / Transport Layer Security"
        }
        
        print("\n🌐 Network Security Basics:")
        for term, definition in concepts.items():
            print(f"{term}: {definition}")
    
    @staticmethod
    def common_ports() -> Dict[int, str]:
        """Commonly used ports"""
        ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            3389: "RDP",
            5432: "PostgreSQL",
            3306: "MySQL",
            1433: "MSSQL",
            6379: "Redis",
            27017: "MongoDB"
        }
        
        print("\n🔌 Common Network Ports:")
        for port, service in ports.items():
            print(f"{port}: {service}")
            
        return ports

# Usage examples and demonstrations
if __name__ == "__main__":
    examples = BasicSecurityExamples()
    
    print("🔐 BASIC SECURITY EXAMPLES DEMONSTRATION")
    print("=" * 50)
    
    # Buffer overflow example
    payload = examples.buffer_overflow_example()
    
    # SQL injection examples
    sql_payloads = examples.sql_injection_examples()
    
    # Validation comparison
    examples.demonstrate_validation_difference()
    
    # XSS examples
    xss_payloads = examples.xss_examples()
    
    # Encoding examples
    examples.demonstrate_encoding()
    
    # Password security
    examples.password_security_examples()
    examples.hash_password_examples()
    
    # Phishing indicators
    phishing_indicators = examples.phishing_indicators()
    
    # Suspicious email analysis
    suspicious_email = """
    Subject: Urgent! Account Verification Required
    
    Dear Customer,
    Suspicious activity has been detected on your account. 
    Please click the link below immediately to verify your account:
    http://yourbank-security.tk/verify
    Otherwise your account will be closed.
    """
    
    analysis = examples.analyze_suspicious_email(suspicious_email)
    print(f"\n📧 Email Analysis Result:")
    print(f"Risk Score: {analysis['risk_score']}")
    print(f"Risk Level: {analysis['risk_level']}")
    print(f"Suspicious Keywords: {analysis['suspicious_keywords']}")
    print(f"Suspicious Domains: {analysis['suspicious_domains']}")
    
    # Network security basics
    examples.network_security_basics()
    
    # Common ports
    common_ports = examples.common_ports()
    
    print("\n✅ Basic Security Examples completed!")
    print("⚠️  Remember: These examples are for educational purposes only!")