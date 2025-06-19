# 🎯 Seviye 0 - Temel Kavramlar

> **Hedef**: Siber güvenlik dünyasına giriş yapmak için gerekli temel kavramları öğrenmek

## 📚 İçindekiler

1. [Siber Güvenlik Nedir?](#siber-güvenlik-nedir)
2. [Temel Terminoloji](#temel-terminoloji)
3. [Güvenlik Üçgeni (CIA Triad)](#güvenlik-üçgeni-cia-triad)
4. [Tehdit Türleri](#tehdit-türleri)
5. [Güvenlik Açığı vs Exploit](#güvenlik-açığı-vs-exploit)
6. [Pratik Egzersizler](#pratik-egzersizler)

---

## 🛡️ Siber Güvenlik Nedir?

**Siber güvenlik**, dijital sistemleri, ağları ve verileri kötü niyetli saldırılardan koruma sanatı ve bilimidir.

### 🎯 Ana Hedefler:
- **Veri Koruma**: Hassas bilgilerin güvenliğini sağlamak
- **Sistem Bütünlüğü**: Sistemlerin doğru çalışmasını garanti etmek
- **Erişilebilirlik**: Yetkili kullanıcıların sisteme erişimini sağlamak
- **Uyumluluk**: Yasal ve düzenleyici gereklilikleri karşılamak

---

## 📖 Temel Terminoloji

### 🔑 Kritik Kavramlar

| Terim | Tanım | Örnek |
|-------|-------|-------|
| **Asset (Varlık)** | Korunması gereken değerli kaynak | Sunucu, veri, yazılım |
| **Threat (Tehdit)** | Potansiyel zarar verici olay | Hacker saldırısı, malware |
| **Vulnerability (Güvenlik Açığı)** | Sistemdeki zayıflık | Güncellenmeyen yazılım |
| **Risk** | Tehdit x Güvenlik Açığı x Etki | Veri kaybı riski |
| **Attack Vector** | Saldırı yöntemi | Email, USB, web sitesi |
| **Payload** | Saldırının zararlı kısmı | Virus kodu, backdoor |
| **Zero-day** | Bilinmeyen güvenlik açığı | Henüz keşfedilmemiş bug |
| **APT** | Gelişmiş Kalıcı Tehdit | Uzun süreli hedefli saldırı |

### 🎭 Saldırgan Türleri

#### 🎩 White Hat (Beyaz Şapka)
- **Tanım**: Etik hacker, güvenlik uzmanı
- **Amaç**: Sistemleri korumak ve güçlendirmek
- **Yöntem**: Yasal izinle penetrasyon testi
- **Örnek**: Güvenlik danışmanı, bug bounty hunter

#### 🎩 Black Hat (Siyah Şapka)
- **Tanım**: Kötü niyetli hacker
- **Amaç**: Kişisel çıkar, zarar verme
- **Yöntem**: İllegal saldırılar
- **Örnek**: Ransomware grupları, veri hırsızları

#### 🎩 Gray Hat (Gri Şapka)
- **Tanım**: Arada kalan hacker
- **Amaç**: Karışık motivasyonlar
- **Yöntem**: Bazen yasal, bazen değil
- **Örnek**: İzinsiz güvenlik açığı bulan araştırmacı

---

## 🔺 Güvenlik Üçgeni (CIA Triad)

### 🔒 Confidentiality (Gizlilik)
**Tanım**: Bilginin sadece yetkili kişiler tarafından erişilebilir olması

**Koruma Yöntemleri**:
- 🔐 Şifreleme (Encryption)
- 🔑 Erişim kontrolü (Access Control)
- 👤 Kimlik doğrulama (Authentication)
- 🛡️ Veri maskeleme (Data Masking)

**Saldırı Örnekleri**:
- Veri sızıntısı
- Şifre kırma
- Social engineering
- Man-in-the-middle

### ✅ Integrity (Bütünlük)
**Tanım**: Verinin doğru, tam ve değiştirilmemiş olması

**Koruma Yöntemleri**:
- 🔍 Hash fonksiyonları (MD5, SHA-256)
- ✍️ Dijital imzalar
- 📝 Audit logları
- 🔄 Backup ve versiyonlama

**Saldırı Örnekleri**:
- Veri manipülasyonu
- SQL injection
- File tampering
- Replay attacks

### 🌐 Availability (Erişilebilirlik)
**Tanım**: Sistemin ihtiyaç duyulduğunda erişilebilir olması

**Koruma Yöntemleri**:
- 🔄 Yedekleme (Backup)
- ⚖️ Yük dengeleme (Load Balancing)
- 🛡️ DDoS koruması
- 🔧 Failover sistemleri

**Saldırı Örnekleri**:
- DDoS saldırıları
- Ransomware
- Hardware arızaları
- Network kesintileri

---

## ⚠️ Tehdit Türleri

### 🦠 Malware (Kötü Amaçlı Yazılım)

#### 🐛 Virus
- **Tanım**: Kendini kopyalayan zararlı kod
- **Yayılma**: Dosya ekleri, USB
- **Etki**: Dosya bozma, sistem yavaşlatma
- **Örnek**: ILOVEYOU, Melissa

#### 🐴 Trojan Horse
- **Tanım**: Yararlı görünen zararlı yazılım
- **Yayılma**: Sahte yazılım indirmeleri
- **Etki**: Backdoor, veri hırsızlığı
- **Örnek**: Zeus, Emotet

#### 🐛 Worm
- **Tanım**: Ağ üzerinden yayılan malware
- **Yayılma**: Otomatik ağ taraması
- **Etki**: Ağ trafiği tıkanması
- **Örnek**: Conficker, WannaCry

#### 🔒 Ransomware
- **Tanım**: Dosyaları şifreleyen fidye yazılımı
- **Yayılma**: Email, exploit kitleri
- **Etki**: Veri erişim kaybı
- **Örnek**: CryptoLocker, Ryuk

### 🎣 Social Engineering

#### 📧 Phishing
- **Tanım**: Sahte email ile bilgi çalma
- **Hedef**: Kullanıcı kimlik bilgileri
- **Yöntem**: Sahte web siteleri
- **Korunma**: Email doğrulama, eğitim

#### 📱 Smishing
- **Tanım**: SMS ile phishing
- **Hedef**: Mobil kullanıcılar
- **Yöntem**: Sahte SMS linkler
- **Korunma**: SMS linklerine dikkat

#### 📞 Vishing
- **Tanım**: Telefon ile phishing
- **Hedef**: Kişisel bilgiler
- **Yöntem**: Sahte telefon görüşmeleri
- **Korunma**: Telefon doğrulama

### 🌐 Network Saldırıları

#### 👥 Man-in-the-Middle (MITM)
- **Tanım**: İletişimi dinleme/değiştirme
- **Yöntem**: ARP spoofing, DNS hijacking
- **Etki**: Veri çalma, oturum hijacking
- **Korunma**: HTTPS, VPN

#### 💥 Denial of Service (DoS)
- **Tanım**: Servisi kullanılamaz hale getirme
- **Yöntem**: Trafik bombardımanı
- **Etki**: Sistem çökmesi
- **Korunma**: Rate limiting, firewall

#### 💥💥 Distributed DoS (DDoS)
- **Tanım**: Çoklu kaynaklı DoS
- **Yöntem**: Botnet kullanımı
- **Etki**: Büyük ölçekli kesinti
- **Korunma**: CDN, DDoS koruması

---

## 🔍 Güvenlik Açığı vs Exploit

### 🕳️ Vulnerability (Güvenlik Açığı)
**Tanım**: Sistemdeki zayıflık veya hata

**Türleri**:
- **Software Bug**: Kod hatası
- **Configuration Error**: Yanlış ayar
- **Design Flaw**: Tasarım hatası
- **Human Error**: İnsan hatası

**Örnekleri**:
```bash
# Zayıf şifre politikası
Password: 123456

# Güncellenmeyen sistem
Apache 2.2.15 (CVE-2017-7679)

# Açık port
Port 22 (SSH) - Public access

# SQL Injection açığı
SELECT * FROM users WHERE id = '$user_input'
```

### ⚔️ Exploit
**Tanım**: Güvenlik açığını kullanan kod/teknik

**Türleri**:
- **Remote Exploit**: Uzaktan çalıştırılan
- **Local Exploit**: Yerel sistem üzerinde
- **Zero-day Exploit**: Bilinmeyen açık için
- **Public Exploit**: Herkese açık

**Örnekleri**:
```python
# Buffer Overflow Exploit
import struct

buffer = "A" * 1024
ret_addr = struct.pack("<I", 0x41414141)
payload = buffer + ret_addr

# SQL Injection Exploit
payload = "1' OR '1'='1' --"
url = f"http://target.com/login?id={payload}"
```

---

## 🛠️ Pratik Egzersizler

### 📝 Egzersiz 1: Terminoloji Testi

**Soru 1**: Aşağıdaki senaryoları CIA Triad'a göre sınıflandırın:

a) Bir hacker banka veritabanındaki müşteri bilgilerini çalıyor
b) Ransomware saldırısı sonucu dosyalara erişilemiyor
c) Saldırgan web sitesindeki fiyat bilgilerini değiştiriyor

**Cevaplar**:
- a) Confidentiality (Gizlilik) ihlali
- b) Availability (Erişilebilirlik) ihlali  
- c) Integrity (Bütünlük) ihlali

### 📝 Egzersiz 2: Tehdit Analizi

**Senaryo**: Şirketinize şu email geldi:

```
Konu: Acil! Hesap Doğrulama Gerekli
Gönderen: security@bankaniz.com

Sayın Müşterimiz,

Hesabınızda şüpheli aktivite tespit edildi. 
Hemen aşağıdaki linke tıklayarak hesabınızı doğrulayın:

http://bankaniz-guvenlik.tk/dogrula

Aksi takdirde hesabınız kapatılacaktır.

Saygılarımızla,
Güvenlik Ekibi
```

**Analiz Soruları**:
1. Bu hangi tür saldırıdır?
2. Şüpheli unsurlar nelerdir?
3. Nasıl korunabilirsiniz?

**Cevaplar**:
1. **Phishing** saldırısı
2. Şüpheli unsurlar:
   - Aciliyet yaratma
   - Sahte domain (.tk)
   - Tehdit içeren dil
   - Genel hitap
3. Korunma yöntemleri:
   - URL'yi kontrol etme
   - Bankayı arayarak doğrulama
   - Direkt banka sitesine gitme
   - Email'i spam olarak işaretleme

### 📝 Egzersiz 3: Risk Hesaplama

**Senaryo**: Web sunucunuzda şu durumlar var:

| Varlık | Tehdit | Güvenlik Açığı | Olasılık | Etki |
|--------|--------|----------------|----------|------|
| Web Server | SQL Injection | Filtrelenmemiş input | Yüksek (8/10) | Yüksek (9/10) |
| Database | Veri Sızıntısı | Zayıf şifreleme | Orta (5/10) | Çok Yüksek (10/10) |
| Admin Panel | Brute Force | Zayıf şifre | Yüksek (7/10) | Yüksek (8/10) |

**Risk Hesaplama Formülü**: Risk = Olasılık × Etki

**Hesaplayın**:
1. Web Server riski: 8 × 9 = 72 (Kritik)
2. Database riski: 5 × 10 = 50 (Yüksek)
3. Admin Panel riski: 7 × 8 = 56 (Yüksek)

**Öncelik Sırası**: Web Server > Admin Panel > Database

---

## 📚 Ek Kaynaklar

### 📖 Önerilen Okumalar
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CVE Database](https://cve.mitre.org/)
- [SANS Reading Room](https://www.sans.org/reading-room/)

### 🎥 Video Kaynakları
- [Professor Messer Security+](https://www.professormesser.com/)
- [Cybrary Fundamentals](https://www.cybrary.it/)
- [SANS Cyber Aces](https://cyberaces.org/)

### 🛠️ Pratik Platformlar
- [TryHackMe - Pre Security](https://tryhackme.com/path/outline/presecurity)
- [Cybrary - IT & Cyber Security](https://www.cybrary.it/)
- [SANS Cyber Aces](https://cyberaces.org/)

---

## ✅ Seviye 0 Tamamlama Kriterleri

### 📋 Bilgi Kontrolü
- [ ] CIA Triad'ı açıklayabilme
- [ ] Temel tehditleri tanımlayabilme
- [ ] Güvenlik açığı vs exploit farkını bilme
- [ ] Risk hesaplama yapabilme
- [ ] Saldırgan türlerini ayırt edebilme

### 🎯 Pratik Beceriler
- [ ] Phishing emaillerini tespit edebilme
- [ ] Temel güvenlik değerlendirmesi yapabilme
- [ ] Güvenlik terminolojisini kullanabilme
- [ ] Risk analizi yapabilme

### 📈 Sonraki Adım
**Seviye 1'e geçiş için hazır mısınız?**

✅ Tüm kriterleri karşıladıysanız → [Seviye 1 - Başlangıç](../level-1/network-security.md)

❌ Eksik alanlarınız varsa → Bu bölümü tekrar gözden geçirin

---

**🎯 Hedef Tamamlandı**: Siber güvenlik temellerini öğrendiniz!

**📚 Sonraki Ders**: [Ağ Temelleri](./networking-fundamentals.md)

---

*Son güncelleme: 2025 | Seviye: Başlangıç | Süre: 1 hafta*