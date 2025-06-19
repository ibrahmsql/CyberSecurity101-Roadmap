# Penetration Testing Basics

## 1. Executive Summary

### Subject Overview and Importance
Penetration testing is the process of systematically testing an organization's information systems for security vulnerabilities in a controlled manner. This discipline is one of the most critical components of the cybersecurity field and evaluates defense mechanisms by simulating methods that real attackers could use.

### Learning Objectives
- Understanding and applying penetration testing methodologies
- Grasping ethical hacking principles
- Vulnerability detection and exploit development
- Preparing comprehensive penetration testing reports
- Understanding legal and ethical boundaries

### Real-World Applications
- Corporate security assessments
- Compliance requirements (PCI DSS, ISO 27001)
- Red team operations
- Security consulting services

## 2. Theoretical Foundation

### Conceptual Explanation

#### What is Penetration Testing?
Penetration testing (pen test) is an authorized simulated attack performed on a computer system, network, or web application to find security vulnerabilities. This test evaluates the security posture of the system using techniques that real attackers might employ.

#### Basic Principles
1. **Authorization**: Written permission must be obtained before each test
2. **Scope Definition**: Systems to be tested must be clearly defined
3. **Minimal Damage**: Minimum harm should be caused to systems
4. **Confidentiality**: Obtained information must be kept confidential
5. **Reporting**: Detailed and understandable reports must be prepared

### Historical Context

#### Development Process
- **1960s**: First security tests (Tiger Teams)
- **1990s**: Commercial penetration testing services
- **2000s**: Methodology standardization
- **2010s**: Development of automated tools
- **2020s**: Cloud and DevSecOps integration

### Current State of the Art

#### Modern Penetration Testing
- **Continuous Security Testing**: DevSecOps integration
- **AI-Powered Testing**: Machine learning-supported tools
- **Cloud-Native Testing**: Container and serverless security
- **Purple Team Approach**: Red and Blue team collaboration

## 3. Technical Deep Dive

### Penetration Testing Methodologies

#### OWASP Testing Guide
```
1. Information Gathering
   ├── Passive Information Gathering
   ├── Active Information Gathering
   └── Application Fingerprinting

2. Configuration Management Testing
   ├── SSL/TLS Configuration
   ├── Database Configuration
   └── Infrastructure Configuration

3. Authentication Testing
   ├── Credential Transport
   ├── Session Management
   └── Password Policy

4. Authorization Testing
   ├── Path Traversal
   ├── Privilege Escalation
   └── Access Control

5. Session Management Testing
   ├── Session Token Analysis
   ├── Session Fixation
   └── Session Timeout
```

#### PTES (Penetration Testing Execution Standard)
```
1. Pre-engagement Interactions
   ├── Scoping
   ├── Rules of Engagement
   └── Legal Agreements

2. Intelligence Gathering
   ├── OSINT
   ├── Social Engineering
   └── Physical Security

3. Threat Modeling
   ├── Asset Identification
   ├── Threat Analysis
   └── Vulnerability Assessment

4. Vulnerability Analysis
   ├── Vulnerability Validation
   ├── Research
   └── Proof of Concept

5. Exploitation
   ├── Precision Strikes
   ├── Customized Exploits
   └── Persistence

6. Post Exploitation
   ├── Infrastructure Analysis
   ├── Pillaging
   └── Cleanup

7. Reporting
   ├── Executive Summary
   ├── Technical Details
   └── Remediation
```

#### NIST SP 800-115
```
Phase 1: Planning
├── Rules of Engagement
├── Test Plan Development
└── Resource Allocation

Phase 2: Discovery
├── Network Discovery
├── Host Discovery
└── Service Discovery

Phase 3: Attack
├── Gaining Access
├── Escalating Privileges
└── System Browsing

Phase 4: Reporting
├── Cleanup
├── Report Generation
└── Remediation Support
```

### Security Implications

#### Risk Assessment Matrix
```
Impact vs Likelihood:

CRITICAL  │ H  │ C  │ C  │ C  │
HIGH      │ M  │ H  │ H  │ C  │
MEDIUM    │ L  │ M  │ M  │ H  │
LOW       │ L  │ L  │ L  │ M  │
          └────┴────┴────┴────┘
           LOW  MED  HIGH CRIT
           
L = Low Risk
M = Medium Risk  
H = High Risk
C = Critical Risk
```

## 4. Hands-on Laboratory

### Lab Setup Requirements

#### Hardware Requirements
- **CPU**: Intel i5/AMD Ryzen 5 or higher
- **RAM**: Minimum 16GB (32GB recommended)
- **Storage**: 500GB SSD
- **Network**: Gigabit Ethernet

#### Software Requirements
```bash
# Hypervisor Installation
# VMware Workstation Pro (Recommended)
wget https://download3.vmware.com/software/wkst/file/VMware-Workstation-Full-17.0.0-20800274.x86_64.bundle
sudo chmod +x VMware-Workstation-Full-17.0.0-20800274.x86_64.bundle
sudo ./VMware-Workstation-Full-17.0.0-20800274.x86_64.bundle

# VirtualBox (Free Alternative)
sudo apt update
sudo apt install virtualbox virtualbox-ext-pack
```

### Virtual Laboratory Setup

#### 1. Kali Linux Installation
```bash
# Download Kali Linux ISO
wget https://cdimage.kali.org/kali-2024.1/kali-linux-2024.1-installer-amd64.iso

# VM Specifications
# RAM: 4GB
# Storage: 80GB
# Network: NAT + Host-Only
```

#### 2. Vulnerable Applications Installation

##### DVWA (Damn Vulnerable Web Application)
```bash
# DVWA installation with Docker
docker pull vulnerables/web-dvwa
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# Manual installation
git clone https://github.com/digininja/DVWA.git
cd DVWA
sudo apt install apache2 mysql-server php php-mysqli php-gd libapache2-mod-php
sudo cp -r DVWA /var/www/html/
sudo chown -R www-data:www-data /var/www/html/DVWA
```

##### Metasploitable 3
```bash
# Installation with Vagrant
vagrant init rapid7/metasploitable3-ub1404
vagrant up

# Manual installation
wget https://github.com/rapid7/metasploitable3/releases/download/v2.0.0/metasploitable3-ub1404.box
vagrant box add metasploitable3 metasploitable3-ub1404.box
```

### Practical Exercises

#### Exercise 1: Network Discovery
```bash
#!/bin/bash
# Network Discovery Script

echo "[+] Starting Network Discovery"

# Host Discovery
echo "[+] Discovering live hosts..."
nmap -sn 192.168.1.0/24 | grep "Nmap scan report" | awk '{print $5}'

# Port Scanning
echo "[+] Scanning common ports..."
nmap -sS -O -sV --top-ports 1000 192.168.1.0/24

# Service Enumeration
echo "[+] Enumerating services..."
nmap -sC -sV -p- 192.168.1.100

echo "[+] Discovery completed"
```

#### Exercise 2: Web Application Testing
```python
#!/usr/bin/env python3
# Web Application Security Scanner

import requests
import sys
from urllib.parse import urljoin
from bs4 import BeautifulSoup

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
    
    def generate_report(self):
        """Generate vulnerability report"""
        print("\n" + "="*50)
        print("VULNERABILITY REPORT")
        print("="*50)
        
        if not self.vulnerabilities:
            print("No vulnerabilities found.")
            return
        
        for vuln in self.vulnerabilities:
            print(f"\nType: {vuln['type']}")
            print(f"URL: {vuln['url']}")
            print(f"Payload: {vuln['payload']}")
            print(f"Severity: {vuln['severity']}")
            print("-" * 30)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 web_scanner.py <target_url>")
        sys.exit(1)
    
    scanner = WebScanner(sys.argv[1])
    vulnerabilities = scanner.scan()
    scanner.generate_report()
```

### Troubleshooting Guide

#### Common Issues

1. **Network Connectivity Problems**
```bash
# Check network configuration
ip addr show
ip route show

# Test connectivity
ping -c 4 8.8.8.8
nslookup google.com

# Fix network issues
sudo dhclient -r
sudo dhclient
```

2. **Tool Installation Issues**
```bash
# Update package lists
sudo apt update && sudo apt upgrade

# Fix broken packages
sudo apt --fix-broken install

# Clean package cache
sudo apt autoclean
sudo apt autoremove
```

3. **Permission Issues**
```bash
# Add user to required groups
sudo usermod -aG sudo $USER
sudo usermod -aG wireshark $USER

# Set proper permissions
sudo chmod +x /usr/local/bin/custom_tool
sudo chown $USER:$USER /home/$USER/tools/
```

## 5. Code Examples

### Automated Reconnaissance Script
```python
#!/usr/bin/env python3
# Advanced Reconnaissance Tool

import subprocess
import json
import sys
import threading
from datetime import datetime
import argparse

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
    
    def generate_report(self, output_file=None):
        """Generate comprehensive report"""
        report = json.dumps(self.results, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"[+] Report saved to {output_file}")
        else:
            print(report)

def main():
    parser = argparse.ArgumentParser(description='Advanced Reconnaissance Tool')
    parser.add_argument('target', help='Target domain or IP address')
    parser.add_argument('-o', '--output', help='Output file for report')
    
    args = parser.parse_args()
    
    recon = ReconTool(args.target)
    recon.run_all_scans()
    recon.generate_report(args.output)

if __name__ == "__main__":
    main()
```

## 6. Tools and Technologies

### Recommended Tools

#### Network Scanning Tools
```bash
# Nmap - Network Mapper
sudo apt install nmap

# Masscan - High-speed port scanner
sudo apt install masscan

# Zmap - Internet-wide scanning
sudo apt install zmap

# Angry IP Scanner
wget https://github.com/angryip/ipscan/releases/download/3.9.1/ipscan_3.9.1_amd64.deb
sudo dpkg -i ipscan_3.9.1_amd64.deb
```

#### Web Application Testing
```bash
# Burp Suite Community
wget https://portswigger.net/burp/releases/download?product=community&version=2024.1.1.4&type=Linux

# OWASP ZAP
sudo apt install zaproxy

# Gobuster
sudo apt install gobuster

# SQLmap
sudo apt install sqlmap

# Nikto
sudo apt install nikto
```

#### Exploitation Frameworks
```bash
# Metasploit Framework
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall

# Cobalt Strike (Commercial)
# Download from official website

# Empire
git clone https://github.com/EmpireProject/Empire.git
cd Empire
sudo ./setup/install.sh
```

## 7. Real-world Case Studies

### Case Study 1: E-commerce Platform Assessment

#### Background
A security assessment was conducted on an e-commerce platform. The platform was a critical system processing 10,000+ transactions daily.

#### Methodology
1. **Reconnaissance Phase**
   - Domain enumeration
   - Technology stack identification
   - Employee information gathering

2. **Vulnerability Assessment**
   - Automated scanning
   - Manual testing
   - Code review

3. **Exploitation Phase**
   - SQL injection exploitation
   - XSS payload development
   - Privilege escalation

#### Key Findings
```
CRITICAL VULNERABILITIES:
├── SQL Injection in payment module
├── Stored XSS in admin panel
└── Insecure direct object references

HIGH VULNERABILITIES:
├── Missing authentication on API endpoints
├── Weak session management
└── Insufficient input validation

MEDIUM VULNERABILITIES:
├── Information disclosure
├── Missing security headers
└── Weak password policy
```

#### Impact Assessment
- **Financial**: Potential $2M+ loss from data breach
- **Reputation**: Customer trust degradation
- **Compliance**: PCI DSS violations
- **Legal**: GDPR compliance issues

#### Remediation
1. **Immediate Actions** (0-30 days)
   - Patch SQL injection vulnerabilities
   - Implement WAF rules
   - Update authentication mechanisms

2. **Short-term Actions** (1-3 months)
   - Code review and secure development training
   - Implement security testing in CI/CD
   - Deploy SIEM solution

3. **Long-term Actions** (3-12 months)
   - Security architecture redesign
   - Regular penetration testing
   - Security awareness program

### Case Study 2: Healthcare Network Penetration

#### Background
Security assessment of a hospital network. Critical importance due to HIPAA compliance requirements.

#### Challenges
- Medical device integration
- 24/7 availability requirements
- Sensitive patient data protection
- Legacy system compatibility

#### Approach
```
Phase 1: External Assessment
├── Internet-facing services
├── Email security testing
└── Social engineering simulation

Phase 2: Internal Network Assessment
├── Network segmentation testing
├── Medical device security
└── Active Directory assessment

Phase 3: Wireless Security
├── WiFi security assessment
├── Bluetooth device enumeration
└── IoT device testing
```

#### Critical Findings
1. **Unpatched Medical Devices**
   - 15+ devices with known CVEs
   - Default credentials on imaging systems
   - Unencrypted network communications

2. **Network Segmentation Issues**
   - Flat network architecture
   - Medical devices on same VLAN as workstations
   - Insufficient access controls

3. **Data Protection Gaps**
   - Unencrypted patient data transmission
   - Weak database access controls
   - Insufficient audit logging

#### Lessons Learned
- Medical environments require specialized testing approaches
- Coordination with clinical staff is essential
- Compliance frameworks provide security baselines
- Legacy systems present unique challenges

## 8. Assessment and Validation

### Knowledge Check Questions

#### Beginner Level
1. **What are the main phases of penetration testing according to PTES?**
   - A) Planning, Discovery, Attack, Reporting
   - B) Reconnaissance, Scanning, Exploitation, Cleanup
   - C) Pre-engagement, Intelligence Gathering, Threat Modeling, Vulnerability Analysis, Exploitation, Post Exploitation, Reporting
   - D) Information Gathering, Vulnerability Assessment, Exploitation, Documentation

2. **Which tool is primarily used for network discovery and port scanning?**
   - A) Metasploit
   - B) Burp Suite
   - C) Nmap
   - D) Wireshark

3. **What is the difference between black box and white box testing?**

#### Intermediate Level
1. **Explain the OWASP Testing Guide methodology and its key components.**

2. **Design a penetration testing lab environment for web application testing.**

3. **Write a Python script to automate subdomain enumeration.**

#### Advanced Level
1. **Develop a custom Metasploit module for a specific vulnerability.**

2. **Create a comprehensive penetration testing report template.**

3. **Design a red team exercise scenario for a financial institution.**

### Practical Assignments

#### Assignment 1: Basic Network Penetration Test
**Objective**: Perform a complete penetration test on a provided virtual network.

**Requirements**:
- Network discovery and enumeration
- Vulnerability identification
- Exploitation attempts
- Post-exploitation activities
- Comprehensive reporting

**Deliverables**:
- Technical report (15-20 pages)
- Executive summary (2-3 pages)
- Remediation recommendations
- Supporting evidence (screenshots, logs)

#### Assignment 2: Web Application Security Assessment
**Objective**: Conduct a thorough security assessment of a web application.

**Scope**:
- OWASP Top 10 testing
- Business logic flaws
- Authentication and authorization
- Session management
- Input validation

**Tools Required**:
- Burp Suite Professional
- OWASP ZAP
- Custom scripts
- Manual testing techniques

### Performance Metrics

#### Technical Skills Assessment
```
Skill Areas:
├── Network Scanning (Weight: 20%)
│   ├── Tool proficiency
│   ├── Result interpretation
│   └── Custom script development
├── Vulnerability Assessment (Weight: 25%)
│   ├── Automated scanning
│   ├── Manual testing
│   └── False positive identification
├── Exploitation (Weight: 30%)
│   ├── Exploit development
│   ├── Payload customization
│   └── Post-exploitation
└── Reporting (Weight: 25%)
    ├── Technical accuracy
    ├── Business impact assessment
    └── Remediation recommendations
```

#### Certification Preparation

**OSCP Preparation Checklist**:
- [ ] Complete PWK course materials
- [ ] Practice on 50+ vulnerable machines
- [ ] Develop custom exploit scripts
- [ ] Master report writing
- [ ] Time management skills

**CEH Preparation Topics**:
- [ ] Ethical hacking fundamentals
- [ ] Reconnaissance techniques
- [ ] System hacking
- [ ] Web application hacking
- [ ] Wireless network hacking

## 9. Emerging Threats and Future Trends

### AI-Powered Vulnerability Prediction

```python
class VulnerabilityPredictor:
    def __init__(self):
        self.model = None
        self.features = []
        
    def train_model(self, vulnerability_data):
        """Train ML model on historical vulnerability data"""
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler
        
        # Feature engineering
        features = self.extract_features(vulnerability_data)
        labels = vulnerability_data['severity']
        
        # Scale features
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        
        # Train model
        self.model = RandomForestClassifier(n_estimators=100)
        self.model.fit(features_scaled, labels)
        
    def predict_vulnerability(self, code_snippet):
        """Predict vulnerability likelihood in code"""
        features = self.extract_code_features(code_snippet)
        prediction = self.model.predict_proba([features])
        return prediction[0]
        
    def extract_code_features(self, code):
        """Extract features from code for vulnerability prediction"""
        features = {
            'input_validation': self.check_input_validation(code),
            'sql_patterns': self.check_sql_patterns(code),
            'crypto_usage': self.check_crypto_usage(code),
            'auth_patterns': self.check_auth_patterns(code)
        }
        return list(features.values())
```

### Quantum-Resistant Penetration Testing

```python
class QuantumResistanceAnalyzer:
    def __init__(self):
        self.quantum_vulnerable_algorithms = [
            'RSA', 'ECDSA', 'DH', 'ECDH'
        ]
        self.quantum_resistant_algorithms = [
            'CRYSTALS-Kyber', 'CRYSTALS-Dilithium', 
            'FALCON', 'SPHINCS+'
        ]
        
    def analyze_cryptographic_implementation(self, target):
        """Analyze target for quantum vulnerability"""
        results = {
            'vulnerable_algorithms': [],
            'resistant_algorithms': [],
            'recommendations': []
        }
        
        # Scan for cryptographic implementations
        crypto_usage = self.scan_crypto_usage(target)
        
        for algorithm in crypto_usage:
            if algorithm in self.quantum_vulnerable_algorithms:
                results['vulnerable_algorithms'].append(algorithm)
                results['recommendations'].append(
                    f"Replace {algorithm} with quantum-resistant alternative"
                )
            elif algorithm in self.quantum_resistant_algorithms:
                results['resistant_algorithms'].append(algorithm)
                
        return results
        
    def generate_migration_plan(self, current_crypto):
        """Generate migration plan to quantum-resistant algorithms"""
        migration_plan = {
            'RSA': 'CRYSTALS-Kyber (Key Exchange) + CRYSTALS-Dilithium (Signatures)',
            'ECDSA': 'CRYSTALS-Dilithium or FALCON',
            'DH': 'CRYSTALS-Kyber',
            'ECDH': 'CRYSTALS-Kyber'
        }
        
        recommendations = []
        for algorithm in current_crypto:
            if algorithm in migration_plan:
                recommendations.append({
                    'current': algorithm,
                    'recommended': migration_plan[algorithm],
                    'priority': 'High' if algorithm in ['RSA', 'ECDSA'] else 'Medium'
                })
                
        return recommendations
```

### Container and Kubernetes Security Assessment

```bash
#!/bin/bash
# Container Security Assessment Script

echo "=== Container Security Assessment ==="

# Check for privileged containers
echo "[+] Checking for privileged containers..."
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.securityContext.privileged}{"\n"}{end}' | grep true

# Check for containers running as root
echo "[+] Checking for containers running as root..."
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.securityContext.runAsUser}{"\n"}{end}' | grep -E "\t0$|\t$"

# Check for exposed services
echo "[+] Checking for exposed services..."
kubectl get services --all-namespaces -o wide

# Check RBAC permissions
echo "[+] Checking RBAC permissions..."
kubectl auth can-i --list --as=system:serviceaccount:default:default

# Check network policies
echo "[+] Checking network policies..."
kubectl get networkpolicies --all-namespaces

# Scan container images for vulnerabilities
echo "[+] Scanning container images..."
for image in $(kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | sort -u); do
    echo "Scanning: $image"
    trivy image $image --severity HIGH,CRITICAL
done
```

### IoT Device Penetration Testing

```python
class IoTDeviceScanner:
    def __init__(self):
        self.common_ports = [21, 22, 23, 80, 443, 8080, 8443]
        self.default_credentials = [
            ('admin', 'admin'), ('admin', 'password'),
            ('root', 'root'), ('admin', '12345')
        ]
        
    def scan_network_devices(self, network_range):
        """Scan network for IoT devices"""
        import nmap
        
        nm = nmap.PortScanner()
        results = []
        
        # Scan for devices
        nm.scan(network_range, arguments='-sn')
        
        for host in nm.all_hosts():
            device_info = self.fingerprint_device(host)
            if device_info['is_iot']:
                results.append(device_info)
                
        return results
        
    def scan_bluetooth_devices(self):
        """Scan for Bluetooth IoT devices"""
        import bluetooth
        
        devices = bluetooth.discover_devices(lookup_names=True)
        iot_devices = []
        
        for addr, name in devices:
            if self.is_iot_device(name):
                device_info = {
                    'address': addr,
                    'name': name,
                    'services': bluetooth.find_service(address=addr)
                }
                iot_devices.append(device_info)
                
        return iot_devices
        
    def fingerprint_device(self, ip):
        """Fingerprint device to identify IoT characteristics"""
        import requests
        import socket
        
        device_info = {
            'ip': ip,
            'is_iot': False,
            'device_type': 'Unknown',
            'vulnerabilities': []
        }
        
        # HTTP fingerprinting
        try:
            response = requests.get(f'http://{ip}', timeout=5)
            if self.check_iot_signatures(response.text, response.headers):
                device_info['is_iot'] = True
                device_info['device_type'] = self.identify_device_type(response)
        except:
            pass
            
        # Port scanning
        open_ports = self.scan_ports(ip)
        device_info['open_ports'] = open_ports
        
        # Check for default credentials
        if 80 in open_ports or 443 in open_ports:
            cred_results = self.test_default_credentials(ip)
            if cred_results:
                device_info['vulnerabilities'].append('Default credentials')
                
        return device_info
        
    def test_default_credentials(self, ip):
        """Test common default credentials"""
        import requests
        from requests.auth import HTTPBasicAuth
        
        for username, password in self.default_credentials:
            try:
                response = requests.get(
                    f'http://{ip}',
                    auth=HTTPBasicAuth(username, password),
                    timeout=5
                )
                if response.status_code == 200:
                    return {'username': username, 'password': password}
            except:
                continue
                
        return None
        
    def generate_report(self, scan_results):
        """Generate IoT security assessment report"""
        report = {
            'total_devices': len(scan_results),
            'vulnerable_devices': 0,
            'critical_issues': [],
            'recommendations': []
        }
        
        for device in scan_results:
            if device['vulnerabilities']:
                report['vulnerable_devices'] += 1
                
            if 'Default credentials' in device['vulnerabilities']:
                report['critical_issues'].append({
                    'device': device['ip'],
                    'issue': 'Default credentials enabled',
                    'severity': 'Critical'
                })
                
        # Generate recommendations
        if report['critical_issues']:
            report['recommendations'].extend([
                'Change all default passwords immediately',
                'Implement network segmentation for IoT devices',
                'Enable firmware auto-updates where possible',
                'Monitor IoT device network traffic'
            ])
            
        return report
```

### Cloud-Native Security Testing

#### Serverless Function Security
```python
# Example: AWS Lambda security testing
def test_lambda_security(function_name):
    import boto3
    
    lambda_client = boto3.client('lambda')
    
    # Get function configuration
    config = lambda_client.get_function_configuration(FunctionName=function_name)
    
    security_issues = []
    
    # Check environment variables for secrets
    env_vars = config.get('Environment', {}).get('Variables', {})
    for key, value in env_vars.items():
        if any(secret in key.lower() for secret in ['password', 'key', 'secret', 'token']):
            security_issues.append(f"Potential secret in environment variable: {key}")
    
    # Check execution role permissions
    role_arn = config['Role']
    # Analyze IAM role permissions (implementation depends on requirements)
    
    return security_issues
```

#### Container Runtime Security
```bash
# Runtime security monitoring
falco --rule-file /etc/falco/falco_rules.yaml --jsonoutput
```

#### Infrastructure as Code Security
```python
# Terraform security scanning
def scan_terraform_files(directory):
    import subprocess
    import json
    
    # Use tfsec for Terraform security scanning
    result = subprocess.run(
        ['tfsec', directory, '--format', 'json'],
        capture_output=True, text=True
    )
    
    if result.returncode == 0:
        findings = json.loads(result.stdout)
        return findings
    else:
        return {'error': result.stderr}
```

### Zero Trust Architecture Testing

#### Micro-segmentation Testing
```python
def test_microsegmentation(network_segments):
    """Test network micro-segmentation effectiveness"""
    results = []
    
    for segment in network_segments:
        # Test lateral movement prevention
        lateral_movement_test = test_lateral_movement(
            segment['source'], segment['target']
        )
        
        results.append({
            'segment': segment['name'],
            'lateral_movement_blocked': lateral_movement_test,
            'policy_enforcement': test_policy_enforcement(segment)
        })
    
    return results
```

#### Identity Verification Testing
```python
def test_identity_verification(identity_provider):
    """Test identity verification mechanisms"""
    tests = {
        'mfa_enforcement': test_mfa_bypass(identity_provider),
        'token_validation': test_token_manipulation(identity_provider),
        'session_management': test_session_hijacking(identity_provider)
    }
    
    return tests
```

## 10. Standards and Frameworks

### Industry Standards
- **NIST SP 800-115**: Technical Guide to Information Security Testing and Assessment
- **OWASP Testing Guide**: Comprehensive web application security testing methodology
- **PTES**: Penetration Testing Execution Standard
- **OSSTMM**: Open Source Security Testing Methodology Manual
- **ISSAF**: Information Systems Security Assessment Framework

### Certification Bodies
- **Offensive Security**: OSCP, OSWE, OSEP
- **EC-Council**: CEH, ECSA, LPT
- **SANS/GIAC**: GPEN, GWAPT, GMOB
- **CompTIA**: PenTest+
- **(ISC)²**: CISSP (Security domain)

## 11. Resources and References

### Academic Publications
- IEEE Security & Privacy Magazine
- ACM Computing Surveys
- Computers & Security Journal
- Journal of Computer Security

### Industry Reports
- Verizon Data Breach Investigations Report
- IBM X-Force Threat Intelligence Index
- SANS Penetration Testing Survey
- Ponemon Institute Security Reports

### Online Learning Platforms
- **HackTheBox**: Hands-on penetration testing labs
- **TryHackMe**: Beginner-friendly security challenges
- **VulnHub**: Vulnerable virtual machines
- **OverTheWire**: Wargames and security challenges
- **PentesterLab**: Web application security exercises

### Community Resources
- **Reddit**: r/netsec, r/AskNetsec, r/penetrationtesting
- **Discord**: Various cybersecurity communities
- **Twitter**: Security researchers and practitioners
- **GitHub**: Open-source security tools and scripts

### Conferences and Events
- **DEF CON**: Annual hacker convention
- **Black Hat**: Information security conference
- **BSides**: Local security conferences
- **OWASP Local Chapters**: Web application security meetups
- **2600 Meetings**: Hacker meetups worldwide

### Essential Books
- "The Web Application Hacker's Handbook" by Dafydd Stuttard
- "Metasploit: The Penetration Tester's Guide" by David Kennedy
- "The Hacker Playbook" series by Peter Kim
- "Penetration Testing: A Hands-On Introduction to Hacking" by Georgia Weidman
- "Advanced Penetration Testing" by Wil Allsopp

### Tool Documentation
- **Nmap**: https://nmap.org/book/
- **Metasploit**: https://docs.rapid7.com/metasploit/
- **Burp Suite**: https://portswigger.net/burp/documentation
- **OWASP ZAP**: https://www.zaproxy.org/docs/
- **Kali Linux**: https://www.kali.org/docs/

---

**Note**: This document provides a comprehensive foundation for penetration testing. Regular updates and continuous learning are essential due to the rapidly evolving nature of cybersecurity threats and technologies.

**Last Updated**: 2024
**Version**: 2.0
**Authors**: Cybersecurity Education Team