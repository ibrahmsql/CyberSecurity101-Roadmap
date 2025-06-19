# 🌐 Seviye 0 - Ağ Temelleri

> **Hedef**: Siber güvenlik için kritik olan ağ kavramlarını ve protokollerini öğrenmek

## 📚 İçindekiler

1. [OSI Modeli](#osi-modeli)
2. [TCP/IP Protokol Ailesi](#tcpip-protokol-ailesi)
3. [IP Adresleme](#ip-adresleme)
4. [Ağ Cihazları](#ağ-cihazları)
5. [DNS (Domain Name System)](#dns-domain-name-system)
6. [DHCP (Dynamic Host Configuration Protocol)](#dhcp-dynamic-host-configuration-protocol)
7. [Ağ Güvenliği Temelleri](#ağ-güvenliği-temelleri)
8. [Pratik Laboratuvarlar](#pratik-laboratuvarlar)

---

## 🏗️ OSI Modeli

**OSI (Open Systems Interconnection)** modeli, ağ iletişimini 7 katmanda açıklayan referans modeldir.

### 📊 OSI Katmanları

| Katman | İsim | Fonksiyon | Protokol Örnekleri | Güvenlik Tehditleri |
|--------|------|-----------|-------------------|--------------------|
| **7** | Application | Kullanıcı arayüzü | HTTP, HTTPS, FTP, SMTP | Malware, Phishing |
| **6** | Presentation | Veri formatı, şifreleme | SSL/TLS, JPEG, MPEG | Şifreleme saldırıları |
| **5** | Session | Oturum yönetimi | NetBIOS, RPC, SQL | Session hijacking |
| **4** | Transport | Uçtan uca iletim | TCP, UDP | Port scanning, DoS |
| **3** | Network | Yönlendirme | IP, ICMP, OSPF, BGP | IP spoofing, routing attacks |
| **2** | Data Link | Çerçeve oluşturma | Ethernet, WiFi, PPP | ARP spoofing, MAC flooding |
| **1** | Physical | Fiziksel iletim | Kablolar, hub, repeater | Fiziksel erişim, wiretapping |

### 🔍 Katman Detayları

#### 🔴 Layer 7 - Application Layer
**Fonksiyon**: Kullanıcı uygulamaları ile ağ arasında arayüz

**Protokoller**:
```bash
# Web Trafiği
HTTP  - Port 80  (Şifrelenmemiş)
HTTPS - Port 443 (SSL/TLS ile şifrelenmiş)

# Email
SMTP - Port 25  (Gönderme)
POP3 - Port 110 (Alma)
IMAP - Port 143 (Alma)

# Dosya Transferi
FTP  - Port 21  (Şifrelenmemiş)
SFTP - Port 22  (SSH ile şifrelenmiş)

# Uzak Erişim
SSH  - Port 22  (Güvenli)
Telnet - Port 23 (Güvensiz)
RDP  - Port 3389 (Windows)
```

**Güvenlik Tehditleri**:
- **Web Saldırıları**: XSS, SQL Injection, CSRF
- **Email Saldırıları**: Phishing, malware ekleri
- **Malware**: Trojan, virus, ransomware

#### 🟠 Layer 4 - Transport Layer
**Fonksiyon**: Güvenilir veri iletimi ve hata kontrolü

**TCP vs UDP Karşılaştırması**:

| Özellik | TCP | UDP |
|---------|-----|-----|
| **Bağlantı** | Connection-oriented | Connectionless |
| **Güvenilirlik** | Güvenilir | Güvenilir değil |
| **Hız** | Yavaş | Hızlı |
| **Overhead** | Yüksek | Düşük |
| **Kullanım** | Web, email, dosya transferi | Video, oyun, DNS |

**TCP Three-Way Handshake**:
```
Client          Server
  |               |
  |---> SYN ----->|
  |<-- SYN-ACK <--|
  |---> ACK ----->|
  |               |
  | Bağlantı Kuruldu |
```

#### 🟡 Layer 3 - Network Layer
**Fonksiyon**: Paketlerin yönlendirilmesi ve adreslemesi

**IP Header Yapısı**:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 🌐 TCP/IP Protokol Ailesi

### 📋 Protokol Katmanları

```
Application Layer    |  HTTP, HTTPS, FTP, SMTP, DNS, DHCP
Transport Layer      |  TCP, UDP
Internet Layer       |  IP, ICMP, ARP
Network Access Layer |  Ethernet, WiFi
```

### 🔍 Önemli Protokoller

#### 🌍 IP (Internet Protocol)
**IPv4 vs IPv6**:

| Özellik | IPv4 | IPv6 |
|---------|------|------|
| **Adres Uzunluğu** | 32 bit | 128 bit |
| **Adres Sayısı** | ~4.3 milyar | ~340 undecillion |
| **Format** | 192.168.1.1 | 2001:db8::1 |
| **Header Boyutu** | 20-60 byte | 40 byte |
| **Güvenlik** | İsteğe bağlı | Yerleşik IPSec |

#### 🔄 ICMP (Internet Control Message Protocol)
**Fonksiyon**: Hata raporlama ve ağ tanılama

**ICMP Mesaj Türleri**:
```bash
# Ping (Echo Request/Reply)
Type 8  - Echo Request
Type 0  - Echo Reply

# Traceroute
Type 11 - Time Exceeded
Type 3  - Destination Unreachable

# Hata Mesajları
Type 3  - Destination Unreachable
Type 4  - Source Quench
Type 5  - Redirect
```

#### 🔗 ARP (Address Resolution Protocol)
**Fonksiyon**: IP adresini MAC adresine çevirme

**ARP Süreci**:
```
1. Host A: "192.168.1.100'ün MAC adresi nedir?" (Broadcast)
2. Host B: "192.168.1.100 benim, MAC adresim: aa:bb:cc:dd:ee:ff"
3. Host A: ARP tablosuna kaydeder
4. İletişim başlar
```

---

## 🏠 IP Adresleme

### 📍 IPv4 Adres Sınıfları

| Sınıf | Aralık | Varsayılan Subnet | Kullanım |
|-------|--------|-------------------|----------|
| **A** | 1.0.0.0 - 126.255.255.255 | /8 (255.0.0.0) | Büyük ağlar |
| **B** | 128.0.0.0 - 191.255.255.255 | /16 (255.255.0.0) | Orta ağlar |
| **C** | 192.0.0.0 - 223.255.255.255 | /24 (255.255.255.0) | Küçük ağlar |
| **D** | 224.0.0.0 - 239.255.255.255 | - | Multicast |
| **E** | 240.0.0.0 - 255.255.255.255 | - | Deneysel |

### 🏠 Özel IP Aralıkları (RFC 1918)

```bash
# Sınıf A
10.0.0.0/8        (10.0.0.0 - 10.255.255.255)
# 16,777,216 adres

# Sınıf B  
172.16.0.0/12     (172.16.0.0 - 172.31.255.255)
# 1,048,576 adres

# Sınıf C
192.168.0.0/16    (192.168.0.0 - 192.168.255.255)
# 65,536 adres

# Loopback
127.0.0.0/8       (127.0.0.0 - 127.255.255.255)
# Yerel test

# Link-Local
169.254.0.0/16    (169.254.0.0 - 169.254.255.255)
# DHCP başarısız olduğunda
```

### 🔢 Subnetting

**CIDR Notasyonu**:
```bash
# /24 = 255.255.255.0
192.168.1.0/24
# Network: 192.168.1.0
# Broadcast: 192.168.1.255
# Host aralığı: 192.168.1.1 - 192.168.1.254
# Host sayısı: 254

# /25 = 255.255.255.128
192.168.1.0/25
# Network: 192.168.1.0
# Broadcast: 192.168.1.127
# Host aralığı: 192.168.1.1 - 192.168.1.126
# Host sayısı: 126
```

**Subnet Hesaplama Tablosu**:

| CIDR | Subnet Mask | Host Sayısı | Subnet Sayısı |
|------|-------------|-------------|---------------|
| /24 | 255.255.255.0 | 254 | 1 |
| /25 | 255.255.255.128 | 126 | 2 |
| /26 | 255.255.255.192 | 62 | 4 |
| /27 | 255.255.255.224 | 30 | 8 |
| /28 | 255.255.255.240 | 14 | 16 |
| /29 | 255.255.255.248 | 6 | 32 |
| /30 | 255.255.255.252 | 2 | 64 |

---

## 🔧 Ağ Cihazları

### 🔄 Hub (Katman 1)
**Özellikler**:
- Fiziksel katman cihazı
- Collision domain paylaşımı
- Half-duplex iletişim
- Güvenlik riski yüksek

**Güvenlik Sorunları**:
- Tüm trafiği tüm portlara gönderir
- Sniffing saldırılarına açık
- Collision'lar performansı düşürür

### 🔀 Switch (Katman 2)
**Özellikler**:
- MAC adres tablosu tutar
- Her port ayrı collision domain
- Full-duplex iletişim
- VLAN desteği

**MAC Adres Tablosu**:
```
Port | MAC Address       | VLAN
-----|-------------------|-----
1    | aa:bb:cc:dd:ee:ff | 10
2    | 11:22:33:44:55:66 | 10
3    | ff:ee:dd:cc:bb:aa | 20
```

**Güvenlik Özellikleri**:
- Port security
- VLAN segmentasyonu
- MAC address filtering
- Storm control

### 🛣️ Router (Katman 3)
**Özellikler**:
- IP paketlerini yönlendirir
- Farklı ağları birbirine bağlar
- Routing tablosu tutar
- NAT/PAT desteği

**Routing Tablosu**:
```
Destination     Gateway         Interface
0.0.0.0/0      192.168.1.1     eth0
192.168.1.0/24 0.0.0.0         eth0
10.0.0.0/8     192.168.1.254   eth0
```

### 🛡️ Firewall
**Türleri**:
- **Packet Filter**: Katman 3-4 filtreleme
- **Stateful**: Bağlantı durumu takibi
- **Application**: Katman 7 inceleme
- **Next-Gen**: Gelişmiş tehdit koruması

---

## 🌐 DNS (Domain Name System)

### 🏗️ DNS Hiyerarşisi

```
                    . (Root)
                   /|\
                  / | \
               com org net gov edu
              /
           google
          /      \
        www      mail
```

### 🔍 DNS Kayıt Türleri

| Tür | Açıklama | Örnek |
|-----|----------|-------|
| **A** | IPv4 adresi | google.com → 172.217.14.206 |
| **AAAA** | IPv6 adresi | google.com → 2607:f8b0:4004:c1b::65 |
| **CNAME** | Takma ad | www.google.com → google.com |
| **MX** | Mail sunucusu | google.com → gmail-smtp-in.l.google.com |
| **NS** | Name server | google.com → ns1.google.com |
| **PTR** | Reverse DNS | 8.8.8.8 → dns.google |
| **TXT** | Metin kaydı | SPF, DKIM kayıtları |
| **SOA** | Authority | Zone bilgileri |

### 🔄 DNS Çözümleme Süreci

```
1. Client: "www.google.com nedir?"
2. Local DNS: Root server'a sorar
3. Root: ".com" server adresini verir
4. Local DNS: .com server'a sorar
5. .com: "google.com" server adresini verir
6. Local DNS: google.com server'a sorar
7. google.com: "www.google.com = 172.217.14.206"
8. Local DNS: Client'a cevap verir
```

### ⚠️ DNS Güvenlik Tehditleri

#### 🎯 DNS Spoofing/Poisoning
**Saldırı**: Sahte DNS cevapları gönderme
```bash
# Saldırgan sahte cevap gönderir
www.bank.com → 192.168.1.100 (saldırgan IP)
# Gerçek cevap yerine
www.bank.com → 203.0.113.10 (gerçek IP)
```

#### 🌊 DNS Amplification
**Saldırı**: DNS sunucularını DDoS için kullanma
```bash
# Küçük sorgu (60 byte)
dig ANY google.com @8.8.8.8

# Büyük cevap (3000+ byte)
# Amplification factor: 50x
```

#### 🕳️ DNS Tunneling
**Saldırı**: DNS üzerinden veri kaçırma
```bash
# Veri DNS sorgusuna gömülür
ZGF0YS10by1leGZpbHRyYXRl.malicious.com
# Base64 encoded data
```

---

## 🔧 DHCP (Dynamic Host Configuration Protocol)

### 🔄 DHCP Süreci (DORA)

```
1. DISCOVER  - Client: "DHCP server var mı?" (Broadcast)
2. OFFER     - Server: "IP adresi teklifi" (Unicast)
3. REQUEST   - Client: "Bu IP'yi istiyorum" (Broadcast)
4. ACK       - Server: "Onaylandı, kullanabilirsin" (Unicast)
```

### 📋 DHCP Seçenekleri

| Seçenek | Açıklama | Örnek |
|---------|----------|-------|
| **1** | Subnet Mask | 255.255.255.0 |
| **3** | Default Gateway | 192.168.1.1 |
| **6** | DNS Server | 8.8.8.8, 8.8.4.4 |
| **15** | Domain Name | company.local |
| **51** | Lease Time | 86400 (24 saat) |
| **66** | TFTP Server | 192.168.1.100 |
| **67** | Boot File | pxelinux.0 |

### ⚠️ DHCP Güvenlik Tehditleri

#### 🎭 DHCP Spoofing
**Saldırı**: Sahte DHCP sunucusu kurma
```bash
# Saldırgan sahte DHCP server kurar
# Kendi IP'sini gateway olarak verir
# Tüm trafiği kendine yönlendirir
```

#### 💥 DHCP Starvation
**Saldırı**: Tüm IP adreslerini tüketme
```bash
# Binlerce sahte MAC ile IP talep etme
# DHCP pool'unu tüketme
# Yeni client'lar IP alamaz
```

---

## 🛡️ Ağ Güvenliği Temelleri

### 🔥 Firewall Kuralları

**Temel Kural Yapısı**:
```bash
# iptables örneği
# Gelen SSH trafiğine izin ver
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Web trafiğine izin ver
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Ping'e izin ver
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Varsayılan olarak reddet
iptables -P INPUT DROP
```

### 🔍 Port Scanning

**Nmap Tarama Türleri**:
```bash
# TCP SYN Scan (Stealth)
nmap -sS target.com

# TCP Connect Scan
nmap -sT target.com

# UDP Scan
nmap -sU target.com

# Service Version Detection
nmap -sV target.com

# OS Detection
nmap -O target.com

# Aggressive Scan
nmap -A target.com
```

### 🕵️ Network Monitoring

**Wireshark Filtreleri**:
```bash
# HTTP trafiği
http

# Belirli IP'den gelen trafik
ip.src == 192.168.1.100

# Belirli porta giden trafik
tcp.dstport == 80

# DNS sorguları
dns

# ICMP paketleri
icmp

# TCP SYN paketleri
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

---

## 🧪 Pratik Laboratuvarlar

### 🔬 Lab 1: Ağ Keşfi

**Hedef**: Yerel ağdaki cihazları keşfetmek

**Araçlar**: `nmap`, `arp-scan`, `ping`

**Adımlar**:
```bash
# 1. Kendi IP adresinizi öğrenin
ip addr show
# veya
ifconfig

# 2. Ağ aralığını tarayın
nmap -sn 192.168.1.0/24

# 3. ARP tablosunu kontrol edin
arp -a

# 4. Aktif cihazları listeleyin
arp-scan -l

# 5. Belirli bir cihazı detaylı tarayın
nmap -A 192.168.1.1
```

**Beklenen Çıktı**:
```
Nmap scan report for 192.168.1.1
Host is up (0.001s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.0
53/tcp   open  domain  dnsmasq 2.80
80/tcp   open  http    nginx 1.18.0
443/tcp  open  https   nginx 1.18.0
```

### 🔬 Lab 2: DNS Analizi

**Hedef**: DNS sorgularını analiz etmek

**Araçlar**: `dig`, `nslookup`, `host`

**Adımlar**:
```bash
# 1. Temel DNS sorgusu
dig google.com

# 2. Belirli kayıt türü sorgusu
dig google.com MX
dig google.com AAAA
dig google.com TXT

# 3. Reverse DNS sorgusu
dig -x 8.8.8.8

# 4. DNS sunucusu belirtme
dig @8.8.8.8 google.com

# 5. Trace sorgusu
dig +trace google.com
```

### 🔬 Lab 3: Paket Analizi

**Hedef**: Ağ trafiğini analiz etmek

**Araçlar**: `tcpdump`, `wireshark`

**Adımlar**:
```bash
# 1. Tüm trafiği yakala
sudo tcpdump -i eth0

# 2. HTTP trafiğini yakala
sudo tcpdump -i eth0 port 80

# 3. Belirli host'tan trafiği yakala
sudo tcpdump -i eth0 host google.com

# 4. Dosyaya kaydet
sudo tcpdump -i eth0 -w capture.pcap

# 5. Dosyadan oku
tcpdump -r capture.pcap
```

### 🔬 Lab 4: Güvenlik Taraması

**Hedef**: Ağ güvenlik açıklarını tespit etmek

**Araçlar**: `nmap`, `nikto`, `dirb`

**Adımlar**:
```bash
# 1. Port taraması
nmap -sS -O -sV target.com

# 2. Güvenlik açığı taraması
nmap --script vuln target.com

# 3. Web sunucu taraması
nikto -h http://target.com

# 4. Dizin taraması
dirb http://target.com

# 5. SSL/TLS testi
nmap --script ssl-enum-ciphers -p 443 target.com
```

---

## 📚 Ek Kaynaklar

### 📖 Önerilen Kitaplar
- "Computer Networking: A Top-Down Approach" - Kurose & Ross
- "TCP/IP Illustrated" - W. Richard Stevens
- "Network Security Essentials" - William Stallings
- "Wireshark Network Analysis" - Laura Chappell

### 🛠️ Pratik Araçlar
```bash
# Ağ keşfi
nmap, masscan, zmap

# Paket analizi
wireshark, tcpdump, tshark

# DNS araçları
dig, nslookup, host, dnsrecon

# Ağ test
ping, traceroute, mtr, iperf

# Güvenlik tarama
nikto, dirb, gobuster, wfuzz
```

### 🌐 Online Kaynaklar
- [Wireshark University](https://www.wiresharktraining.com/)
- [Packet Life](http://packetlife.net/)
- [NetworkLessons.com](https://networklessons.com/)
- [Cisco Networking Academy](https://www.netacad.com/)

---

## ✅ Seviye 0 - Ağ Temelleri Tamamlama Kriterleri

### 📋 Teorik Bilgi
- [ ] OSI modelini açıklayabilme
- [ ] TCP/IP protokol ailesini bilme
- [ ] IP adresleme ve subnetting
- [ ] DNS çalışma prensibini anlama
- [ ] DHCP sürecini bilme
- [ ] Ağ cihazlarının fonksiyonlarını bilme

### 🛠️ Pratik Beceriler
- [ ] Nmap ile ağ taraması yapabilme
- [ ] Wireshark ile paket analizi
- [ ] DNS sorgularını yapabilme
- [ ] Temel firewall kuralları yazabilme
- [ ] Ağ sorunlarını teşhis edebilme

### 🎯 Lab Tamamlama
- [ ] Lab 1: Ağ keşfi tamamlandı
- [ ] Lab 2: DNS analizi tamamlandı
- [ ] Lab 3: Paket analizi tamamlandı
- [ ] Lab 4: Güvenlik taraması tamamlandı

### 📈 Sonraki Adım
**Seviye 1'e geçiş için hazır mısınız?**

✅ Tüm kriterleri karşıladıysanız → [Seviye 1 - Ağ Güvenliği](../level-1/network-security.md)

❌ Eksik alanlarınız varsa → Bu bölümü tekrar gözden geçirin

---

**🎯 Hedef Tamamlandı**: Ağ temellerini öğrendiniz!

**📚 Sonraki Ders**: [İşletim Sistemleri](./operating-systems.md)

---

*Son güncelleme: 2025 | Seviye: Başlangıç | Süre: 1 hafta*