# 🌐 Level 0 - Networking Fundamentals

> **Goal**: Learn network concepts and protocols critical for cybersecurity

## 📚 Table of Contents

1. [OSI Model](#osi-model)
2. [TCP/IP Protocol Suite](#tcpip-protocol-suite)
3. [IP Addressing](#ip-addressing)
4. [Network Devices](#network-devices)
5. [DNS (Domain Name System)](#dns-domain-name-system)
6. [DHCP (Dynamic Host Configuration Protocol)](#dhcp-dynamic-host-configuration-protocol)
7. [Network Security Fundamentals](#network-security-fundamentals)
8. [Practical Labs](#practical-labs)

---

## 🏗️ OSI Model

**OSI (Open Systems Interconnection)** model is a reference model that describes network communication in 7 layers.

### 📊 OSI Layers

| Layer | Name | Function | Protocol Examples | Security Threats |
|-------|------|----------|-------------------|-----------------|
| **7** | Application | User interface | HTTP, HTTPS, FTP, SMTP | Malware, Phishing |
| **6** | Presentation | Data format, encryption | SSL/TLS, JPEG, MPEG | Encryption attacks |
| **5** | Session | Session management | NetBIOS, RPC, SQL | Session hijacking |
| **4** | Transport | End-to-end transmission | TCP, UDP | Port scanning, DoS |
| **3** | Network | Routing | IP, ICMP, OSPF, BGP | IP spoofing, routing attacks |
| **2** | Data Link | Frame creation | Ethernet, WiFi, PPP | ARP spoofing, MAC flooding |
| **1** | Physical | Physical transmission | Cables, hub, repeater | Physical access, wiretapping |

### 🔍 Layer Details

#### 🔴 Layer 7 - Application Layer
**Function**: Interface between user applications and network

**Protocols**:
```bash
# Web Traffic
HTTP  - Port 80  (Unencrypted)
HTTPS - Port 443 (Encrypted with SSL/TLS)

# Email
SMTP - Port 25  (Sending)
POP3 - Port 110 (Receiving)
IMAP - Port 143 (Receiving)

# File Transfer
FTP  - Port 21  (Unencrypted)
SFTP - Port 22  (Encrypted with SSH)

# Remote Access
SSH  - Port 22  (Secure)
Telnet - Port 23 (Insecure)
RDP  - Port 3389 (Windows)
```

**Security Threats**:
- **Web Attacks**: XSS, SQL Injection, CSRF
- **Email Attacks**: Phishing, malware attachments
- **Malware**: Trojan, virus, ransomware

#### 🟠 Layer 4 - Transport Layer
**Function**: Reliable data transmission and error control

**TCP vs UDP Comparison**:

| Feature | TCP | UDP |
|---------|-----|-----|
| **Connection** | Connection-oriented | Connectionless |
| **Reliability** | Reliable | Unreliable |
| **Speed** | Slow | Fast |
| **Overhead** | High | Low |
| **Usage** | Web, email, file transfer | Video, gaming, DNS |

**TCP Three-Way Handshake**:
```
Client          Server
  |               |
  |---> SYN ----->|
  |<-- SYN-ACK <--|
  |---> ACK ----->|
  |               |
  | Connection Established |
```

#### 🟡 Layer 3 - Network Layer
**Function**: Packet routing and addressing

**IP Header Structure**:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 🌐 TCP/IP Protocol Suite

**TCP/IP** is the fundamental protocol suite of the internet.

### 📊 TCP/IP Model vs OSI Model

| TCP/IP Layer | OSI Equivalent | Protocols |
|--------------|----------------|----------|
| **Application** | Application, Presentation, Session | HTTP, FTP, SMTP, DNS |
| **Transport** | Transport | TCP, UDP |
| **Internet** | Network | IP, ICMP, ARP |
| **Network Access** | Data Link, Physical | Ethernet, WiFi |

### 🔍 Key Protocols

#### 🌍 Internet Protocol (IP)
- **IPv4**: 32-bit addresses (4.3 billion addresses)
- **IPv6**: 128-bit addresses (340 undecillion addresses)

**IPv4 Address Classes**:
```
Class A: 1.0.0.0   - 126.255.255.255 (/8)
Class B: 128.0.0.0 - 191.255.255.255 (/16)
Class C: 192.0.0.0 - 223.255.255.255 (/24)
Class D: 224.0.0.0 - 239.255.255.255 (Multicast)
Class E: 240.0.0.0 - 255.255.255.255 (Reserved)
```

#### 🚀 Internet Control Message Protocol (ICMP)
**Purpose**: Error reporting and network diagnostics

**Common ICMP Messages**:
```bash
# Ping (Echo Request/Reply)
ping google.com

# Traceroute (Time Exceeded)
traceroute google.com

# Destination Unreachable
# Port Unreachable
# Network Unreachable
```

---

## 🏠 IP Addressing

### 📍 IPv4 Addressing

#### 🔢 Subnet Mask
**Purpose**: Separates network and host portions

**CIDR Notation Examples**:
```
192.168.1.0/24   = 255.255.255.0   (256 addresses)
192.168.1.0/25   = 255.255.255.128 (128 addresses)
192.168.1.0/26   = 255.255.255.192 (64 addresses)
192.168.1.0/27   = 255.255.255.224 (32 addresses)
```

#### 🏠 Private IP Ranges
```
Class A: 10.0.0.0/8        (10.0.0.0 - 10.255.255.255)
Class B: 172.16.0.0/12     (172.16.0.0 - 172.31.255.255)
Class C: 192.168.0.0/16    (192.168.0.0 - 192.168.255.255)
```

#### 🌐 Special IP Addresses
```
127.0.0.1       - Loopback (localhost)
0.0.0.0         - Default route
255.255.255.255 - Broadcast
169.254.x.x     - APIPA (Automatic Private IP)
```

### 🆕 IPv6 Addressing

**Format**: 8 groups of 4 hexadecimal digits
```
2001:0db8:85a3:0000:0000:8a2e:0370:7334
2001:db8:85a3::8a2e:370:7334  (Compressed)
```

**IPv6 Address Types**:
- **Unicast**: Single interface
- **Multicast**: Multiple interfaces
- **Anycast**: Nearest interface

---

## 🔧 Network Devices

### 🔌 Layer 1 Devices (Physical)

#### 📡 Hub
- **Function**: Signal amplification and distribution
- **Collision Domain**: Single collision domain
- **Security**: No security, all data visible to all ports

#### 🔄 Repeater
- **Function**: Signal regeneration
- **Usage**: Extend cable length
- **Limitation**: Cannot filter traffic

### 🔗 Layer 2 Devices (Data Link)

#### 🌉 Switch
- **Function**: Frame forwarding based on MAC addresses
- **MAC Address Table**: Learns and stores MAC addresses
- **Collision Domain**: Each port is separate collision domain

**Switch Operation**:
```
1. Receive frame
2. Check destination MAC address
3. Look up MAC address table
4. Forward to appropriate port
5. Update MAC address table
```

**Security Features**:
- **Port Security**: Limit MAC addresses per port
- **VLAN**: Virtual network segmentation
- **802.1X**: Port-based authentication

### 🛣️ Layer 3 Devices (Network)

#### 🚦 Router
- **Function**: Packet routing between networks
- **Routing Table**: Stores network paths
- **Default Gateway**: Exit point for local network

**Routing Protocols**:
```
Static Routing  - Manual configuration
RIP            - Distance Vector
OSPF           - Link State
BGP            - Path Vector (Internet)
```

---

## 🌐 DNS (Domain Name System)

**Purpose**: Translate domain names to IP addresses

### 🏗️ DNS Hierarchy

```
                    Root (".") 
                       |
            +----------+----------+
            |                     |
          .com                  .org
            |                     |
        google.com            wikipedia.org
            |                     |
        www.google.com        www.wikipedia.org
```

### 📝 DNS Record Types

| Record Type | Purpose | Example |
|-------------|---------|----------|
| **A** | IPv4 address | google.com → 142.250.191.14 |
| **AAAA** | IPv6 address | google.com → 2607:f8b0:4004:c1b::65 |
| **CNAME** | Canonical name | www.google.com → google.com |
| **MX** | Mail exchange | google.com → aspmx.l.google.com |
| **NS** | Name server | google.com → ns1.google.com |
| **PTR** | Reverse lookup | 8.8.8.8 → dns.google |
| **TXT** | Text information | SPF, DKIM records |

### 🔍 DNS Query Process

```
1. User types "www.google.com"
2. Check local DNS cache
3. Query local DNS server
4. Query root DNS server
5. Query .com DNS server
6. Query google.com DNS server
7. Return IP address
8. Connect to web server
```

### ⚠️ DNS Security Threats

#### 🎣 DNS Spoofing/Poisoning
- **Attack**: Fake DNS responses
- **Impact**: Redirect users to malicious sites
- **Prevention**: DNSSEC, secure DNS servers

#### 🌊 DNS Amplification Attack
- **Attack**: Use DNS servers for DDoS
- **Method**: Spoof source IP, large DNS responses
- **Prevention**: Rate limiting, response size limits

---

## 🏠 DHCP (Dynamic Host Configuration Protocol)

**Purpose**: Automatically assign IP addresses to devices

### 🔄 DHCP Process (DORA)

```
Client                    DHCP Server
  |                           |
  |---> DISCOVER (Broadcast)-->|
  |<--- OFFER <---------------|
  |---> REQUEST -------------->|
  |<--- ACK <------------------|
  |                           |
  | IP Address Assigned       |
```

### 📋 DHCP Options

| Option | Purpose | Example |
|--------|---------|----------|
| **3** | Default Gateway | 192.168.1.1 |
| **6** | DNS Server | 8.8.8.8, 8.8.4.4 |
| **15** | Domain Name | company.com |
| **51** | Lease Time | 86400 seconds (24 hours) |

### ⚠️ DHCP Security Threats

#### 🎭 DHCP Spoofing
- **Attack**: Rogue DHCP server
- **Impact**: Man-in-the-middle attacks
- **Prevention**: DHCP snooping, port security

#### 💥 DHCP Starvation
- **Attack**: Exhaust DHCP pool
- **Impact**: Denial of service
- **Prevention**: Rate limiting, monitoring

---

## 🛡️ Network Security Fundamentals

### 🔥 Firewall

**Purpose**: Control network traffic based on security rules

#### 📊 Firewall Types

| Type | Layer | Features |
|------|-------|----------|
| **Packet Filter** | Layer 3-4 | IP, port filtering |
| **Stateful** | Layer 3-4 | Connection tracking |
| **Application** | Layer 7 | Deep packet inspection |
| **Next-Gen** | All layers | IPS, malware detection |

#### 🔧 Firewall Rules

```bash
# Allow HTTP traffic
allow tcp any any port 80

# Block specific IP
deny ip 192.168.1.100 any

# Allow SSH from management network
allow tcp 10.0.0.0/24 any port 22

# Default deny
deny ip any any
```

### 🕵️ Intrusion Detection System (IDS)

**Purpose**: Monitor and detect malicious activities

#### 🔍 IDS Types

**Network-based IDS (NIDS)**:
- Monitors network traffic
- Detects network attacks
- Examples: Snort, Suricata

**Host-based IDS (HIDS)**:
- Monitors system activities
- Detects file changes, logins
- Examples: OSSEC, Tripwire

#### 🚨 Detection Methods

**Signature-based**:
- Known attack patterns
- Low false positives
- Cannot detect new attacks

**Anomaly-based**:
- Baseline behavior analysis
- Detects unknown attacks
- Higher false positives

### 🛡️ Virtual Private Network (VPN)

**Purpose**: Secure communication over public networks

#### 🔐 VPN Protocols

| Protocol | Layer | Security | Performance |
|----------|-------|----------|-------------|
| **PPTP** | Layer 2 | Weak | Fast |
| **L2TP/IPSec** | Layer 2/3 | Strong | Medium |
| **OpenVPN** | Layer 3 | Strong | Medium |
| **WireGuard** | Layer 3 | Strong | Fast |

#### 🏗️ VPN Types

**Site-to-Site VPN**:
- Connects networks
- Always-on connection
- Used for branch offices

**Remote Access VPN**:
- Connects individual users
- On-demand connection
- Used for remote workers

---

## 🧪 Practical Labs

### 🔬 Lab 1: Network Scanning

**Objective**: Discover devices and services on network

**Tools**: Nmap, Netdiscover

```bash
# Ping sweep
nmap -sn 192.168.1.0/24

# Port scan
nmap -sS -p 1-1000 192.168.1.1

# Service detection
nmap -sV 192.168.1.1

# OS detection
nmap -O 192.168.1.1
```

### 🔬 Lab 2: Packet Analysis

**Objective**: Analyze network traffic

**Tools**: Wireshark, tcpdump

```bash
# Capture packets
sudo tcpdump -i eth0 -w capture.pcap

# Filter HTTP traffic
tcpdump -r capture.pcap 'port 80'

# Filter by IP
tcpdump -r capture.pcap 'host 192.168.1.100'
```

**Wireshark Filters**:
```
http                    # HTTP traffic
tcp.port == 80         # Port 80 traffic
ip.addr == 192.168.1.1 # Specific IP
dns                    # DNS queries
```

### 🔬 Lab 3: DNS Analysis

**Objective**: Understand DNS resolution

```bash
# DNS lookup
nslookup google.com

# Reverse DNS lookup
nslookup 8.8.8.8

# Specific record type
dig google.com MX

# Trace DNS path
dig +trace google.com
```

### 🔬 Lab 4: Network Troubleshooting

**Objective**: Diagnose network connectivity issues

```bash
# Test connectivity
ping 8.8.8.8

# Trace route
traceroute google.com

# Check routing table
route -n

# Check network interfaces
ifconfig

# Check listening ports
netstat -tuln
```

---

## 🎯 Security Best Practices

### 🔒 Network Segmentation
- **VLANs**: Separate broadcast domains
- **Subnets**: Logical network division
- **DMZ**: Demilitarized zone for public services
- **Zero Trust**: Never trust, always verify

### 🛡️ Access Control
- **NAC**: Network Access Control
- **802.1X**: Port-based authentication
- **MAC Filtering**: Allow/deny by MAC address
- **Strong Authentication**: Multi-factor authentication

### 📊 Monitoring and Logging
- **SIEM**: Security Information and Event Management
- **Flow Analysis**: NetFlow, sFlow
- **Baseline Monitoring**: Normal behavior patterns
- **Alerting**: Real-time threat notifications

---

## 🎓 Knowledge Check

### ❓ Quiz Questions

1. **How many layers does the OSI model have?**
   - a) 5
   - b) 6
   - c) 7
   - d) 8

2. **Which protocol is connectionless?**
   - a) TCP
   - b) UDP
   - c) HTTP
   - d) FTP

3. **What is the default subnet mask for a Class C network?**
   - a) 255.0.0.0
   - b) 255.255.0.0
   - c) 255.255.255.0
   - d) 255.255.255.255

4. **Which port does HTTPS use?**
   - a) 80
   - b) 443
   - c) 8080
   - d) 8443

5. **What does DNS stand for?**
   - a) Dynamic Name System
   - b) Domain Name Service
   - c) Domain Name System
   - d) Dynamic Network Service

### ✅ Answers
1. c) 7
2. b) UDP
3. c) 255.255.255.0
4. b) 443
5. c) Domain Name System

---

## 📚 Additional Resources

### 📖 Recommended Reading
- "Computer Networking: A Top-Down Approach" by Kurose & Ross
- "TCP/IP Illustrated" by W. Richard Stevens
- "Network Security Essentials" by William Stallings

### 🌐 Online Resources
- [Cisco Networking Academy](https://www.netacad.com/)
- [Wireshark University](https://www.wireshark.org/)
- [RFC Documents](https://www.rfc-editor.org/)

### 🛠️ Tools
- **Wireshark**: Packet analyzer
- **Nmap**: Network scanner
- **Netcat**: Network utility
- **tcpdump**: Command-line packet analyzer

---

## 🎯 Next Steps

After completing this module, you should:

1. **Understand** the OSI and TCP/IP models
2. **Configure** basic network settings
3. **Analyze** network traffic
4. **Identify** common network security threats

**Ready for Level 1?** 🚀

Move on to [Level 1 - System Security](../level-1/system-security.md) to learn about securing individual systems!

---

*This document is part of the CyberSecurity 101 Roadmap. For the complete learning path, visit the [main repository](../../README.md).*