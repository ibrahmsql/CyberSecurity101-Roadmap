#!/usr/bin/env python3
"""
Comprehensive Penetration Testing Framework
Includes web application security scanning, reconnaissance tools, and advanced testing capabilities
"""

import requests
import sys
import subprocess
import json
import threading
import socket
import secrets
import hashlib
import jwt
import bcrypt
from datetime import datetime, timedelta
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import argparse
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import numpy as np

# Web Application Security Scanner
class WebScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
    
    def sql_injection_test(self, url):
        """Test for SQL Injection vulnerabilities"""
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--"
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(url, params={'id': payload})
                if "mysql" in response.text.lower() or "syntax error" in response.text.lower():
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'url': url,
                        'payload': payload,
                        'severity': 'High'
                    })
            except Exception as e:
                print(f"Error testing {url}: {e}")
    
    def xss_test(self, url):
        """Test for Cross-Site Scripting vulnerabilities"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(url, params={'search': payload})
                if payload in response.text:
                    self.vulnerabilities.append({
                        'type': 'Cross-Site Scripting',
                        'url': url,
                        'payload': payload,
                        'severity': 'Medium'
                    })
            except Exception as e:
                print(f"Error testing {url}: {e}")
    
    def directory_traversal_test(self, url):
        """Test for Directory Traversal vulnerabilities"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd"
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(url, params={'file': payload})
                if "root:" in response.text or "[drivers]" in response.text:
                    self.vulnerabilities.append({
                        'type': 'Directory Traversal',
                        'url': url,
                        'payload': payload,
                        'severity': 'High'
                    })
            except Exception as e:
                print(f"Error testing {url}: {e}")
    
    def scan(self):
        """Perform comprehensive scan"""
        print(f"[+] Starting scan of {self.target_url}")
        
        # Test common endpoints
        endpoints = [
            '/login.php',
            '/search.php',
            '/file.php',
            '/admin.php'
        ]
        
        for endpoint in endpoints:
            full_url = urljoin(self.target_url, endpoint)
            print(f"[+] Testing {full_url}")
            
            self.sql_injection_test(full_url)
            self.xss_test(full_url)
            self.directory_traversal_test(full_url)
        
        return self.vulnerabilities

# Advanced Reconnaissance Tool
class ReconTool:
    def __init__(self, target):
        self.target = target
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'nmap_scan': {},
            'dns_info': {},
            'whois_info': {},
            'subdomain_enum': []
        }
    
    def run_nmap_scan(self):
        """Perform comprehensive Nmap scan"""
        print(f"[+] Running Nmap scan on {self.target}")
        
        # TCP SYN scan
        tcp_cmd = f"nmap -sS -sV -O --top-ports 1000 {self.target}"
        tcp_result = subprocess.run(tcp_cmd.split(), capture_output=True, text=True)
        
        # UDP scan (top 100 ports)
        udp_cmd = f"nmap -sU --top-ports 100 {self.target}"
        udp_result = subprocess.run(udp_cmd.split(), capture_output=True, text=True)
        
        self.results['nmap_scan'] = {
            'tcp_scan': tcp_result.stdout,
            'udp_scan': udp_result.stdout
        }
    
    def dns_enumeration(self):
        """Perform DNS enumeration"""
        print(f"[+] Performing DNS enumeration on {self.target}")
        
        dns_records = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        dns_results = {}
        
        for record_type in dns_records:
            cmd = f"dig {self.target} {record_type} +short"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            dns_results[record_type] = result.stdout.strip().split('\n')
        
        self.results['dns_info'] = dns_results
    
    def whois_lookup(self):
        """Perform WHOIS lookup"""
        print(f"[+] Performing WHOIS lookup on {self.target}")
        
        cmd = f"whois {self.target}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        self.results['whois_info'] = result.stdout
    
    def subdomain_enumeration(self):
        """Enumerate subdomains"""
        print(f"[+] Enumerating subdomains for {self.target}")
        
        # Common subdomain wordlist
        subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
            'api', 'blog', 'shop', 'forum', 'support', 'docs'
        ]
        
        found_subdomains = []
        
        for subdomain in subdomains:
            full_domain = f"{subdomain}.{self.target}"
            cmd = f"dig {full_domain} +short"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            
            if result.stdout.strip():
                found_subdomains.append({
                    'subdomain': full_domain,
                    'ip': result.stdout.strip()
                })
        
        self.results['subdomain_enum'] = found_subdomains
    
    def run_all_scans(self):
        """Run all reconnaissance scans"""
        threads = []
        
        # Create threads for parallel execution
        scan_functions = [
            self.run_nmap_scan,
            self.dns_enumeration,
            self.whois_lookup,
            self.subdomain_enumeration
        ]
        
        for func in scan_functions:
            thread = threading.Thread(target=func)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        return self.results

# Secure Web Application Framework
class SecureWebApp:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = secrets.token_hex(32)
        self.setup_security_headers()
        self.setup_routes()
    
    def setup_security_headers(self):
        @self.app.after_request
        def add_security_headers(response):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['Content-Security-Policy'] = "default-src 'self'"
            return response
    
    def generate_csrf_token(self):
        return secrets.token_urlsafe(32)
    
    def validate_csrf_token(self, token, session_token):
        return secrets.compare_digest(token, session_token)
    
    def create_jwt_token(self, user_id):
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, self.app.config['SECRET_KEY'], algorithm='HS256')
    
    def validate_jwt_token(self, token):
        try:
            payload = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
            return payload['user_id']
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def setup_routes(self):
        # Routes would be defined here
        pass

# Access Control Framework
def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                abort(401)  # Unauthorized
            
            user_permissions = get_user_permissions(session['user_id'])
            if permission not in user_permissions:
                abort(403)  # Forbidden
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_user_permissions(user_id):
    """Get user permissions from database"""
    # Database query to get user permissions
    # Implementation depends on your permission model
    return ['admin.users.read', 'admin.users.write']  # Example permissions

# Secure Cryptography Implementation
class SecureCrypto:
    @staticmethod
    def hash_password(password):
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt)
    
    @staticmethod
    def verify_password(password, hashed):
        return bcrypt.checkpw(password.encode('utf-8'), hashed)
    
    @staticmethod
    def generate_encryption_key(password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    @staticmethod
    def encrypt_data(data, key):
        f = Fernet(key)
        return f.encrypt(data.encode())
    
    @staticmethod
    def decrypt_data(encrypted_data, key):
        f = Fernet(key)
        return f.decrypt(encrypted_data).decode()

# Vulnerability Prediction using Machine Learning
class VulnerabilityPredictor:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100)
        self.features = [
            'port_count', 'service_version_age', 'patch_level',
            'configuration_score', 'network_exposure'
        ]
    
    def train_model(self, training_data):
        """Train the vulnerability prediction model"""
        X = training_data[self.features]
        y = training_data['vulnerable']
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        predictions = self.model.predict(X_test)
        print(classification_report(y_test, predictions))
    
    def predict_vulnerability(self, target_features):
        """Predict vulnerability likelihood"""
        probability = self.model.predict_proba([target_features])[0][1]
        return probability
    
    def get_feature_importance(self):
        """Get feature importance scores"""
        importance = dict(zip(self.features, self.model.feature_importances_))
        return sorted(importance.items(), key=lambda x: x[1], reverse=True)

# Quantum Resistance Analyzer
class QuantumResistanceAnalyzer:
    def __init__(self):
        self.vulnerable_algorithms = {
            'RSA': {'key_sizes': [1024, 2048], 'quantum_vulnerable': True},
            'ECC': {'curves': ['P-256', 'P-384'], 'quantum_vulnerable': True},
            'DSA': {'key_sizes': [1024, 2048], 'quantum_vulnerable': True}
        }
        
        self.quantum_resistant = {
            'CRYSTALS-Kyber': {'type': 'KEM', 'security_level': 128},
            'CRYSTALS-Dilithium': {'type': 'Signature', 'security_level': 128},
            'FALCON': {'type': 'Signature', 'security_level': 128}
        }
    
    def analyze_cryptographic_implementation(self, target_system):
        """Analyze cryptographic implementations for quantum resistance"""
        vulnerabilities = []
        
        # Check for quantum-vulnerable algorithms
        for algorithm, details in self.vulnerable_algorithms.items():
            if self.detect_algorithm_usage(target_system, algorithm):
                vulnerabilities.append({
                    'algorithm': algorithm,
                    'vulnerability': 'Quantum vulnerable',
                    'recommendation': f'Migrate to quantum-resistant alternative'
                })
        
        return vulnerabilities
    
    def detect_algorithm_usage(self, target_system, algorithm):
        """Detect usage of specific cryptographic algorithms"""
        # Implementation would involve certificate analysis,
        # TLS handshake inspection, etc.
        # For demonstration, return True
        return True
    
    def recommend_migration_path(self, current_algorithms):
        """Recommend migration to quantum-resistant algorithms"""
        recommendations = {}
        
        for algorithm in current_algorithms:
            if algorithm in ['RSA', 'ECC']:
                recommendations[algorithm] = 'CRYSTALS-Kyber + CRYSTALS-Dilithium'
            elif algorithm == 'DSA':
                recommendations[algorithm] = 'FALCON'
        
        return recommendations

# IoT Device Security Scanner
class IoTScanner:
    def __init__(self):
        self.discovered_devices = []
        self.vulnerabilities = []
    
    def scan_network_devices(self, network_range):
        """Scan for IoT devices on network"""
        print(f"[+] Scanning network range: {network_range}")
        
        # Common IoT device ports
        iot_ports = [80, 443, 8080, 8443, 23, 22, 21, 161, 1883, 5683]
        
        for ip in self.generate_ip_range(network_range):
            for port in iot_ports:
                if self.port_scan(ip, port):
                    device_info = self.fingerprint_device(ip, port)
                    if device_info:
                        self.discovered_devices.append(device_info)
    
    def generate_ip_range(self, network_range):
        """Generate IP addresses from network range"""
        # Simple implementation for demonstration
        base_ip = network_range.split('/')[0]
        base_parts = base_ip.split('.')
        
        for i in range(1, 255):
            yield f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}"
    
    def port_scan(self, ip, port):
        """Scan a specific port on an IP address"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def fingerprint_device(self, ip, port):
        """Fingerprint device based on response"""
        try:
            if port in [80, 8080]:
                response = requests.get(f"http://{ip}:{port}", timeout=5)
                return {
                    'ip': ip,
                    'port': port,
                    'type': 'Web Interface',
                    'headers': dict(response.headers)
                }
        except:
            pass
        
        return None

# Comprehensive Penetration Testing Framework
class PenetrationTestingFramework:
    def __init__(self):
        self.web_scanner = None
        self.recon_tool = None
        self.iot_scanner = IoTScanner()
        self.quantum_analyzer = QuantumResistanceAnalyzer()
        self.vuln_predictor = VulnerabilityPredictor()
        self.results = {}
    
    def web_application_test(self, target_url):
        """Perform web application penetration test"""
        print(f"[+] Starting web application test for {target_url}")
        self.web_scanner = WebScanner(target_url)
        vulnerabilities = self.web_scanner.scan()
        self.results['web_vulnerabilities'] = vulnerabilities
        return vulnerabilities
    
    def reconnaissance(self, target):
        """Perform reconnaissance on target"""
        print(f"[+] Starting reconnaissance for {target}")
        self.recon_tool = ReconTool(target)
        recon_results = self.recon_tool.run_all_scans()
        self.results['reconnaissance'] = recon_results
        return recon_results
    
    def iot_security_assessment(self, network_range):
        """Perform IoT security assessment"""
        print(f"[+] Starting IoT security assessment for {network_range}")
        self.iot_scanner.scan_network_devices(network_range)
        self.results['iot_devices'] = self.iot_scanner.discovered_devices
        return self.iot_scanner.discovered_devices
    
    def quantum_readiness_assessment(self, target_system):
        """Assess quantum readiness of cryptographic implementations"""
        print(f"[+] Assessing quantum readiness for {target_system}")
        vulnerabilities = self.quantum_analyzer.analyze_cryptographic_implementation(target_system)
        self.results['quantum_vulnerabilities'] = vulnerabilities
        return vulnerabilities
    
    def generate_comprehensive_report(self):
        """Generate comprehensive penetration testing report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_vulnerabilities': len(self.results.get('web_vulnerabilities', [])),
                'high_severity': len([v for v in self.results.get('web_vulnerabilities', []) if v.get('severity') == 'High']),
                'medium_severity': len([v for v in self.results.get('web_vulnerabilities', []) if v.get('severity') == 'Medium']),
                'iot_devices_found': len(self.results.get('iot_devices', [])),
                'quantum_vulnerabilities': len(self.results.get('quantum_vulnerabilities', []))
            },
            'detailed_results': self.results
        }
        
        return report
    
    def export_report(self, filename):
        """Export report to JSON file"""
        report = self.generate_comprehensive_report()
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[+] Report exported to {filename}")

# Command Line Interface
def main():
    parser = argparse.ArgumentParser(description='Comprehensive Penetration Testing Framework')
    parser.add_argument('--target', help='Target URL or IP address')
    parser.add_argument('--web-scan', action='store_true', help='Perform web application scan')
    parser.add_argument('--recon', action='store_true', help='Perform reconnaissance')
    parser.add_argument('--iot-scan', help='Perform IoT scan on network range')
    parser.add_argument('--quantum-assess', action='store_true', help='Assess quantum readiness')
    parser.add_argument('--output', default='pentest_report.json', help='Output report filename')
    
    args = parser.parse_args()
    
    if not any([args.web_scan, args.recon, args.iot_scan, args.quantum_assess]):
        parser.print_help()
        return
    
    framework = PenetrationTestingFramework()
    
    if args.web_scan and args.target:
        framework.web_application_test(args.target)
    
    if args.recon and args.target:
        framework.reconnaissance(args.target)
    
    if args.iot_scan:
        framework.iot_security_assessment(args.iot_scan)
    
    if args.quantum_assess and args.target:
        framework.quantum_readiness_assessment(args.target)
    
    framework.export_report(args.output)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main()
    else:
        print("Comprehensive Penetration Testing Framework")
        print("===========================================")
        print("Available modules:")
        print("- Web Application Security Scanner")
        print("- Advanced Reconnaissance Tool")
        print("- IoT Device Security Scanner")
        print("- Quantum Resistance Analyzer")
        print("- Vulnerability Predictor (ML-based)")
        print("\nUse --help for command line options")