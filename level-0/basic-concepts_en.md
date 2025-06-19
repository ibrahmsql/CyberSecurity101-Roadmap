# 🎯 Level 0 - Basic Cybersecurity Concepts

> **Goal**: Learn the fundamental concepts necessary to enter the cybersecurity world

## 📚 Table of Contents

1. [What is Cybersecurity?](#what-is-cybersecurity)
2. [Basic Terminology](#basic-terminology)
3. [Security Triangle (CIA Triad)](#security-triangle-cia-triad)
4. [Threat Types](#threat-types)
5. [Vulnerability vs Exploit](#vulnerability-vs-exploit)
6. [Practical Exercises](#practical-exercises)

---

## 🛡️ What is Cybersecurity?

**Cybersecurity** is the art and science of protecting digital systems, networks, and data from malicious attacks.

### 🎯 Main Objectives:
- **Data Protection**: Ensuring the security of sensitive information
- **System Integrity**: Guaranteeing proper system operation
- **Availability**: Ensuring authorized users can access the system
- **Compliance**: Meeting legal and regulatory requirements

---

## 📖 Basic Terminology

### 🔑 Critical Concepts

| Term | Definition | Example |
|------|------------|----------|
| **Asset** | Valuable resource that needs protection | Server, data, software |
| **Threat** | Potentially harmful event | Hacker attack, malware |
| **Vulnerability** | Weakness in the system | Outdated software |
| **Risk** | Threat x Vulnerability x Impact | Data loss risk |
| **Attack Vector** | Attack method | Email, USB, website |
| **Payload** | Malicious part of the attack | Virus code, backdoor |
| **Zero-day** | Unknown vulnerability | Undiscovered bug |
| **APT** | Advanced Persistent Threat | Long-term targeted attack |

### 🎭 Attacker Types

#### 🎩 White Hat
- **Definition**: Ethical hacker, security expert
- **Purpose**: Protect and strengthen systems
- **Method**: Legal penetration testing with permission
- **Example**: Security consultant, bug bounty hunter

#### 🎩 Black Hat
- **Definition**: Malicious hacker, cybercriminal
- **Purpose**: Personal gain, damage, theft
- **Method**: Illegal attacks, data theft
- **Example**: Ransomware groups, data thieves

#### 🎩 Gray Hat
- **Definition**: Between white and black hat
- **Purpose**: Mixed motivations
- **Method**: Sometimes legal, sometimes illegal
- **Example**: Hacktivists, researchers

---

## 🔺 Security Triangle (CIA Triad)

The **CIA Triad** forms the foundation of information security:

### 🔒 Confidentiality (Gizlilik)
- **Definition**: Information should only be accessible to authorized persons
- **Threats**: Data theft, unauthorized access, espionage
- **Protection Methods**:
  - Encryption
  - Access controls
  - Authentication
  - Authorization

### ✅ Integrity (Bütünlük)
- **Definition**: Data should remain unchanged and accurate
- **Threats**: Data manipulation, corruption, unauthorized modification
- **Protection Methods**:
  - Digital signatures
  - Hash functions
  - Version control
  - Backup systems

### 🌐 Availability (Erişilebilirlik)
- **Definition**: Systems and data should be accessible when needed
- **Threats**: DoS attacks, system failures, natural disasters
- **Protection Methods**:
  - Redundancy
  - Load balancing
  - Disaster recovery
  - Monitoring

---

## ⚠️ Threat Types

### 🦠 Malware
- **Virus**: Self-replicating malicious code
- **Worm**: Network-spreading malware
- **Trojan**: Disguised malicious software
- **Ransomware**: Data encryption for ransom
- **Spyware**: Secret information gathering
- **Adware**: Unwanted advertisement display

### 🎣 Social Engineering
- **Phishing**: Fake emails for information theft
- **Spear Phishing**: Targeted phishing attacks
- **Vishing**: Voice-based fraud
- **Smishing**: SMS-based fraud
- **Pretexting**: False scenario creation
- **Baiting**: Tempting with attractive offers

### 🌊 Network Attacks
- **DDoS**: Distributed Denial of Service
- **Man-in-the-Middle**: Communication interception
- **Packet Sniffing**: Network traffic monitoring
- **ARP Spoofing**: Address resolution manipulation
- **DNS Poisoning**: Domain name system corruption

### 💻 System Attacks
- **Buffer Overflow**: Memory overflow exploitation
- **SQL Injection**: Database query manipulation
- **Cross-Site Scripting (XSS)**: Web application script injection
- **Privilege Escalation**: Unauthorized permission increase
- **Rootkit**: Deep system hiding

---

## 🔍 Vulnerability vs Exploit

### 🕳️ Vulnerability (Güvenlik Açığı)
- **Definition**: Weakness or flaw in a system
- **Examples**:
  - Outdated software
  - Weak passwords
  - Misconfiguration
  - Design flaws

### ⚔️ Exploit
- **Definition**: Code or technique that takes advantage of a vulnerability
- **Types**:
  - **Remote Exploit**: Network-based attack
  - **Local Exploit**: System access required
  - **Zero-day Exploit**: Uses unknown vulnerability
  - **DoS Exploit**: Causes service disruption

### 🔄 Vulnerability Lifecycle
1. **Discovery**: Vulnerability found
2. **Disclosure**: Vendor notification
3. **Patch Development**: Fix creation
4. **Patch Release**: Update distribution
5. **Patch Installation**: User application

---

## 🛠️ Practical Exercises

### 📝 Exercise 1: Risk Assessment
**Scenario**: You are the IT manager of a small company.

**Assets**:
- Customer database
- Financial records
- Email server
- Company website

**Task**: Identify potential threats for each asset and calculate risk levels.

**Solution Template**:
```
Asset: Customer Database
Threats: Data theft, ransomware, insider threat
Vulnerabilities: Weak passwords, outdated software
Impact: High (legal liability, reputation damage)
Probability: Medium
Risk Level: High
```

### 🔍 Exercise 2: Attack Vector Analysis
**Scenario**: Your company received a suspicious email.

**Email Content**:
```
From: security@yourbank.com
Subject: Urgent: Account Verification Required

Dear Customer,
Your account will be suspended in 24 hours.
Click here to verify: http://bit.ly/verify-account
```

**Questions**:
1. What type of attack is this?
2. What are the red flags?
3. How would you respond?
4. What preventive measures would you implement?

### 🧪 Exercise 3: CIA Triad Application
**Scenario**: Design security measures for an online banking system.

**Requirements**:
- Ensure customer data confidentiality
- Maintain transaction integrity
- Guarantee 99.9% availability

**Task**: Propose specific security controls for each CIA component.

### 🎯 Exercise 4: Threat Modeling
**Scenario**: Secure a company's Wi-Fi network.

**Steps**:
1. Identify assets (network infrastructure, connected devices)
2. List threats (unauthorized access, eavesdropping)
3. Find vulnerabilities (weak encryption, default passwords)
4. Assess risks
5. Propose countermeasures

---

## 🎓 Knowledge Check

### ❓ Quiz Questions

1. **What does the CIA Triad stand for?**
   - a) Central Intelligence Agency
   - b) Confidentiality, Integrity, Availability
   - c) Computer Information Assurance
   - d) Cyber Intelligence Analysis

2. **Which is NOT a type of malware?**
   - a) Virus
   - b) Firewall
   - c) Trojan
   - d) Ransomware

3. **What is a zero-day vulnerability?**
   - a) A vulnerability discovered on day zero
   - b) A vulnerability with no impact
   - c) An unknown vulnerability with no available patch
   - d) A vulnerability that expires in zero days

4. **Which attack targets the human element?**
   - a) SQL Injection
   - b) Social Engineering
   - c) Buffer Overflow
   - d) DDoS

5. **What is the main goal of a white hat hacker?**
   - a) Personal financial gain
   - b) System damage
   - c) Improving security
   - d) Data theft

### ✅ Answers
1. b) Confidentiality, Integrity, Availability
2. b) Firewall
3. c) An unknown vulnerability with no available patch
4. b) Social Engineering
5. c) Improving security

---

## 📚 Additional Resources

### 📖 Recommended Reading
- "The Art of Deception" by Kevin Mitnick
- "Security Engineering" by Ross Anderson
- "Hacking: The Art of Exploitation" by Jon Erickson
- "The Web Application Hacker's Handbook" by Dafydd Stuttard

### 🌐 Online Resources
- [OWASP (Open Web Application Security Project)](https://owasp.org/)
- [SANS Institute](https://www.sans.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CVE (Common Vulnerabilities and Exposures)](https://cve.mitre.org/)

### 🎯 Practice Platforms
- [TryHackMe](https://tryhackme.com/)
- [Hack The Box](https://www.hackthebox.eu/)
- [OverTheWire](https://overthewire.org/)
- [VulnHub](https://www.vulnhub.com/)

### 📺 YouTube Channels
- NetworkChuck
- John Hammond
- LiveOverflow
- IppSec

---

## 🎯 Next Steps

After completing Level 0, you should:

1. **Understand** basic cybersecurity concepts
2. **Recognize** common threats and attack vectors
3. **Apply** the CIA Triad to real scenarios
4. **Identify** vulnerabilities and risks

**Ready for Level 1?** 🚀

Move on to [Level 1 - System Security](../level-1/system-security.md) to dive deeper into practical cybersecurity skills!

---

*This document is part of the CyberSecurity 101 Roadmap. For the complete learning path, visit the [main repository](../../README.md).*