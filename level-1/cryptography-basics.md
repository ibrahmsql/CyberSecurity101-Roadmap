#  kriptografi Temelleri

## 🎯 Seviye Hedefi

Bu bölümde, kriptografinin temel kavramlarını, tarihçesini, modern kriptografik algoritmaları ve siber güvenlikteki kritik rolünü öğreneceksiniz. Simetrik ve asimetrik şifreleme, hash fonksiyonları, dijital imzalar ve açık anahtar altyapısı (PKI) gibi temel konulara odaklanılacaktır.

## 📚 Konu Başlıkları

1.  [Executive Summary](#1-executive-summary)
2.  [Giriş: Kriptografi Nedir?](#2-giriş-kriptografi-nedir)
3.  [Temel Kavramlar ve Terminoloji](#3-temel-kavramlar-ve-terminoloji)
4.  [Anahtar Algoritmalar ve Teknikler](#4-anahtar-algoritmalar-ve-teknikler)
5.  [Pratik Uygulamalar ve Kullanım Alanları](#5-pratik-uygulamalar-ve-kullanım-alanları)
6.  [Araçlar ve Teknolojiler](#6-araçlar-ve-teknolojiler)
7.  [En İyi Uygulamalar ve Güvenlik Hususları](#7-en-iyi-uygulamalar-ve-güvenlik-hususları)
8.  [Zorluklar ve Sınırlamalar](#8-zorluklar-ve-sınırlamalar)
9.  [Gelecek Trendler](#9-gelecek-trendler)
10. [Kaynaklar ve Referanslar](#10-kaynaklar-ve-referanslar)

---

## 1. Executive Summary

Kriptografi, bilgiyi yetkisiz erişime karşı korumak için kullanılan matematiksel tekniklerin bilimi ve sanatıdır. Günümüz dijital dünyasında veri gizliliği, bütünlüğü ve kimlik doğrulama için vazgeçilmez bir unsurdur. Bu bölüm, kriptografinin temel taşlarını, modern uygulamalarını ve siber güvenlikteki önemini kapsamlı bir şekilde ele almaktadır.

---

## 2. Giriş: Kriptografi Nedir?

Kriptografi (Yunanca "kryptos" - gizli ve "graphein" - yazmak kelimelerinden gelir), okunabilir bilgiyi (düz metin) anlaşılamaz bir forma (şifreli metin) dönüştürme ve bu işlemi tersine çevirme yöntemlerini inceler. Temel amacı, iletişimin gizliliğini, gönderilen verinin bütünlüğünü, gönderici ve alıcının kimliğinin doğrulanmasını ve işlemlerin inkar edilemezliğini sağlamaktır.

### Kriptografinin Tarihçesi

-   **Antik Çağ:** Sezar şifresi gibi basit yer değiştirme şifreleri.
-   **Orta Çağ ve Rönesans:** Polialfabetik şifreler (Vigenère şifresi).
-   **Dünya Savaşları:** Enigma makinesi gibi mekanik şifreleme cihazları.
-   **Modern Dönem:** Bilgisayarların ve internetin yaygınlaşmasıyla DES, AES, RSA gibi güçlü algoritmaların geliştirilmesi.

### Kriptografinin Siber Güvenlikteki Rolü

-   **Gizlilik (Confidentiality):** Verilerin yetkisiz kişilerce okunmasını engeller (Örn: HTTPS, SSL/TLS).
-   **Bütünlük (Integrity):** Verilerin iletim sırasında değiştirilip değiştirilmediğini kontrol eder (Örn: Hash fonksiyonları, MAC).
-   **Kimlik Doğrulama (Authentication):** Kullanıcıların veya sistemlerin kimliklerini doğrular (Örn: Dijital sertifikalar, parolalar).
-   **İnkar Edilemezlik (Non-repudiation):** Bir işlemin gerçekleştirildiğinin veya bir mesajın gönderildiğinin inkar edilmesini önler (Örn: Dijital imzalar).

---

## 3. Temel Kavramlar ve Terminoloji

-   **Düz Metin (Plaintext):** Şifrelenmemiş, okunabilir orijinal mesaj.
-   **Şifreli Metin (Ciphertext):** Şifreleme algoritması uygulanarak dönüştürülmüş, anlaşılamaz mesaj.
-   **Şifreleme (Encryption):** Düz metni şifreli metne dönüştürme işlemi.
-   **Deşifreleme (Decryption):** Şifreli metni tekrar düz metne dönüştürme işlemi.
-   **Anahtar (Key):** Şifreleme ve deşifreleme işlemlerini kontrol eden gizli bilgi parçası.
-   **Algoritma (Cipher/Algorithm):** Şifreleme ve deşifreleme için kullanılan matematiksel kurallar dizisi.
-   **Kriptanaliz (Cryptanalysis):** Anahtarı bilmeden şifreli metni çözme veya şifreleme sisteminin zayıflıklarını bulma bilimi.
-   **Kriptoloji (Cryptology):** Kriptografi ve kriptanalizi kapsayan genel bilim dalı.

### Güvenlik Hedefleri (CIA Üçgeni ve Ötesi)

-   **Gizlilik (Confidentiality):** Sadece yetkili kişilerin bilgiye erişebilmesi.
-   **Bütünlük (Integrity):** Bilginin yetkisiz değiştirilmeye karşı korunması.
-   **Kullanılabilirlik (Availability):** Yetkili kullanıcıların ihtiyaç duyduklarında bilgiye ve kaynaklara erişebilmesi.
-   **Kimlik Doğrulama (Authentication):** Bir varlığın (kullanıcı, sistem) iddia ettiği kimlik olduğunun doğrulanması.
-   **Yetkilendirme (Authorization):** Doğrulanmış bir kimliğe hangi kaynaklara erişim izni verildiğinin belirlenmesi.
-   **İnkar Edilemezlik (Non-repudiation):** Bir eylemin veya olayın gerçekleştiğinin kanıtlanması, böylece failin bunu inkar edememesi.

---

## 4. Anahtar Algoritmalar ve Teknikler

### a. Simetrik Şifreleme (Gizli Anahtar Kriptografisi)

Şifreleme ve deşifreleme için aynı anahtarın kullanıldığı yöntemdir. Hızlıdır ancak anahtar dağıtımı güvenli bir şekilde yapılmalıdır.

-   **Blok Şifreler (Block Ciphers):** Veriyi sabit boyutlu bloklara böler ve her bloğu ayrı ayrı şifreler.
    -   **DES (Data Encryption Standard):** Eski bir standart, artık güvensiz kabul edilir (56-bit anahtar).
    -   **3DES (Triple DES):** DES'i üç kez uygulayarak güvenliği artırır, ancak yavaştır.
    -   **AES (Advanced Encryption Standard):** Günümüzde yaygın olarak kullanılan güvenli standart (128, 192, 256-bit anahtar).
        -   Çalışma Modları: ECB, CBC, CFB, OFB, CTR.
-   **Akış Şifreleri (Stream Ciphers):** Veriyi bit bit veya byte byte şifreler.
    -   **RC4:** Geçmişte SSL/TLS ve WEP'te kullanıldı, ancak zafiyetleri nedeniyle artık önerilmiyor.
    -   **ChaCha20:** Modern ve güvenli bir akış şifresi, genellikle Poly1305 ile birlikte kullanılır.

**Avantajları:** Hızlı, daha az işlem gücü gerektirir.
**Dezavantajları:** Anahtar dağıtımı zor ve risklidir. Çok sayıda kullanıcı için çok fazla anahtar gerekir.

### b. Asimetrik Şifreleme (Açık Anahtar Kriptografisi)

Şifreleme ve deşifreleme için farklı ancak matematiksel olarak ilişkili iki anahtar kullanılır: açık anahtar (public key) ve gizli anahtar (private key).

-   **Açık Anahtar (Public Key):** Herkesle paylaşılabilir, mesajları şifrelemek veya dijital imzaları doğrulamak için kullanılır.
-   **Gizli Anahtar (Private Key):** Sadece sahibi tarafından bilinir, şifreli mesajları deşifrelemek veya dijital imza oluşturmak için kullanılır.

-   **RSA (Rivest-Shamir-Adleman):** En yaygın kullanılan asimetrik algoritma. Büyük sayıların çarpanlarına ayrılmasının zorluğuna dayanır.
-   **ECC (Elliptic Curve Cryptography):** Eliptik eğriler üzerindeki matematiksel işlemlere dayanır. RSA'ya göre daha kısa anahtar uzunluklarıyla aynı düzeyde güvenlik sağlar, bu da mobil ve IoT cihazlar için idealdir.
-   **Diffie-Hellman Anahtar Değişimi:** İki tarafın güvenli olmayan bir kanal üzerinden ortak bir gizli anahtar oluşturmasını sağlar. Şifreleme için değil, anahtar değişimi için kullanılır.
-   **ElGamal:** Ayrık logaritma probleminin zorluğuna dayanan bir başka asimetrik şifreleme ve dijital imza algoritması.

**Avantajları:** Güvenli anahtar dağıtımı, dijital imzalar ve kimlik doğrulama sağlar.
**Dezavantajları:** Simetrik şifrelemeye göre daha yavaştır ve daha fazla işlem gücü gerektirir.

### c. Hash Fonksiyonları (Özet Fonksiyonları)

Değişken uzunluktaki bir girdiyi (mesaj) sabit uzunlukta benzersiz bir çıktıya (hash değeri veya mesaj özeti) dönüştüren tek yönlü matematiksel fonksiyonlardır. Aynı girdi her zaman aynı çıktıyı üretir, ancak çıktıdan girdiyi elde etmek hesaplama açısından imkansızdır (veya çok zordur).

-   **Özellikleri:**
    -   **Tek Yönlülük (One-way):** Hash değerinden orijinal mesaja geri dönülemez.
    -   **Çakışma Direnci (Collision Resistance):** Farklı iki girdinin aynı hash değerini üretmesi çok zordur.
        -   *Zayıf Çakışma Direnci:* Verilen bir x için, H(x) = H(y) olacak şekilde bir y bulmak zordur.
        -   *Güçlü Çakışma Direnci:* H(x) = H(y) olacak şekilde herhangi bir (x, y) çifti bulmak zordur.
    -   **Deterministik:** Aynı mesaj her zaman aynı hash değerini üretir.
    -   **Çığ Etkisi (Avalanche Effect):** Girdideki küçük bir değişiklik çıktıda büyük bir değişikliğe neden olur.

-   **Yaygın Algoritmalar:**
    -   **MD5 (Message Digest 5):** Artık güvensiz kabul edilir, çakışma zafiyetleri vardır (128-bit).
    -   **SHA-1 (Secure Hash Algorithm 1):** Güvensiz kabul edilir, çakışma zafiyetleri vardır (160-bit).
    -   **SHA-2 Ailesi (SHA-224, SHA-256, SHA-384, SHA-512):** Günümüzde yaygın olarak kullanılan güvenli standartlardır.
    -   **SHA-3 Ailesi (Keccak):** SHA-2'den farklı bir tasarıma sahip yeni nesil standart.
    -   **BLAKE2/BLAKE3:** Hızlı ve güvenli modern hash fonksiyonları.

**Kullanım Alanları:** Veri bütünlüğü kontrolü, parola saklama, dijital imzalar, blokzincir.

### d. Dijital İmzalar

Bir mesajın veya belgenin bütünlüğünü ve göndericisinin kimliğini doğrulamak için asimetrik kriptografi kullanan bir mekanizmadır. Gönderici, mesajı kendi gizli anahtarıyla imzalar; alıcı ise göndericinin açık anahtarını kullanarak imzayı doğrular.

-   **İşleyiş:**
    1.  Gönderici, mesajın hash değerini hesaplar.
    2.  Hesaplanan hash değerini kendi gizli anahtarıyla şifreler (bu dijital imzadır).
    3.  Orijinal mesajı ve dijital imzayı alıcıya gönderir.
    4.  Alıcı, göndericinin açık anahtarını kullanarak dijital imzayı deşifreler (orijinal hash değerini elde eder).
    5.  Alıcı, aldığı orijinal mesajın hash değerini kendisi de hesaplar.
    6.  İki hash değerini karşılaştırır. Eşleşiyorsa, mesajın bütünlüğü ve göndericinin kimliği doğrulanmış olur.

-   **Algoritmalar:** RSA, DSA (Digital Signature Algorithm), ECDSA (Elliptic Curve Digital Signature Algorithm).

### e. Mesaj Kimlik Doğrulama Kodları (MAC - Message Authentication Code)

Bir mesajın hem bütünlüğünü hem de kaynağının doğruluğunu teyit etmek için kullanılan, paylaşılan bir gizli anahtara dayalı kısa bir bilgi parçasıdır. Hash fonksiyonlarına benzer ancak bir gizli anahtar içerir.

-   **HMAC (Hash-based MAC):** Bir hash fonksiyonu (örn: SHA-256) ve bir gizli anahtar kullanır. Örn: HMAC-SHA256.
-   **CMAC (Cipher-based MAC):** Bir blok şifreleme algoritması (örn: AES) ve bir gizli anahtar kullanır.

**Farkı:** Dijital imzalar açık anahtar kriptografisi kullanırken, MAC'ler simetrik (gizli) anahtar kullanır. Bu nedenle MAC'ler, taraflar arasında önceden paylaşılmış bir gizli anahtar gerektirir ve inkar edilemezlik sağlamaz.

### f. Açık Anahtar Altyapısı (PKI - Public Key Infrastructure)

Dijital sertifikaların oluşturulması, yönetilmesi, dağıtılması, kullanılması, saklanması ve iptal edilmesi için gerekli olan roller, politikalar, donanımlar, yazılımlar ve prosedürler bütünüdür. Temel amacı, açık anahtarların güvenilir bir şekilde belirli kimliklere bağlanmasını sağlamaktır.

-   **Bileşenleri:**
    -   **Sertifika Otoritesi (CA - Certificate Authority):** Dijital sertifikaları yayınlayan ve doğrulayan güvenilir üçüncü taraf. (Örn: Let's Encrypt, DigiCert, Comodo).
    -   **Kayıt Otoritesi (RA - Registration Authority):** CA adına kimlik doğrulama işlemlerini yapar.
    -   **Dijital Sertifika:** Bir açık anahtarı bir kimlikle (kişi, sunucu, şirket) ilişkilendiren elektronik belge. X.509 standardı yaygın olarak kullanılır.
        -   İçeriği: Sahibinin adı, açık anahtarı, CA'nın adı, geçerlilik süresi, seri numarası, CA'nın dijital imzası.
    -   **Sertifika İptal Listesi (CRL - Certificate Revocation List):** Artık geçerli olmayan (kompromize olmuş, süresi dolmadan iptal edilmiş) sertifikaların listesi.
    -   **Online Certificate Status Protocol (OCSP):** Bir sertifikanın geçerlilik durumunu gerçek zamanlı olarak sorgulamak için kullanılan protokol.
    -   **Sertifika Deposu (Certificate Repository):** Yayınlanmış sertifikaların ve CRL'lerin saklandığı yer.

---

## 5. Pratik Uygulamalar ve Kullanım Alanları

-   **Güvenli Web İletişimi (HTTPS):** SSL/TLS protokolleri, web sunucuları ve tarayıcılar arasında şifreli bağlantılar kurmak için asimetrik ve simetrik kriptografi ile dijital sertifikaları kullanır.
-   **E-posta Güvenliği:**
    -   **PGP (Pretty Good Privacy) / GPG (GNU Privacy Guard):** E-postaları şifrelemek ve imzalamak için kullanılır.
    -   **S/MIME (Secure/Multipurpose Internet Mail Extensions):** E-postalara dijital imza ve şifreleme eklemek için X.509 sertifikalarını kullanır.
-   **Veri Saklama Güvenliği (Data at Rest):**
    -   **Tam Disk Şifrelemesi (FDE - Full Disk Encryption):** BitLocker (Windows), FileVault (macOS), LUKS (Linux) gibi araçlarla tüm sabit diski şifreler.
    -   **Dosya/Klasör Şifrelemesi:** Belirli dosyaları veya klasörleri şifrelemek için kullanılır (Örn: VeraCrypt, AxCrypt).
    -   **Veritabanı Şifrelemesi:** Veritabanlarındaki hassas verileri korumak için kullanılır.
-   **Sanal Özel Ağlar (VPN):** Güvenli olmayan ağlar (örn: internet) üzerinden özel ağlara güvenli erişim sağlamak için şifreli tüneller oluşturur (IPSec, OpenVPN).
-   **Kablosuz Ağ Güvenliği:** WPA2/WPA3 protokolleri, kablosuz ağ trafiğini şifrelemek için AES gibi algoritmalar kullanır.
-   **Dijital Para Birimleri (Kripto Paralar):** Bitcoin, Ethereum gibi kripto paralar, işlemleri güvence altına almak, yeni birimler oluşturmak ve sahiplik doğrulamak için hash fonksiyonları ve dijital imzalar gibi kriptografik teknikleri yoğun bir şekilde kullanır (Blokzincir teknolojisi).
-   **Kimlik Yönetimi ve Erişim Kontrolü:** Parola hash'leme, akıllı kartlar, biyometrik sistemler.
-   **Yazılım Güvenliği:** Kod imzalama, yazılım güncellemelerinin bütünlüğünü doğrulamak için kullanılır.
-   **Nesnelerin İnterneti (IoT) Güvenliği:** Kaynak kısıtlı IoT cihazlarında veri gizliliği ve bütünlüğü için hafif kriptografik çözümler.

---

## 6. Araçlar ve Teknolojiler

-   **OpenSSL:** SSL/TLS protokollerinin açık kaynaklı bir uygulamasıdır ve genel amaçlı bir kriptografi kütüphanesidir. Sertifika yönetimi, şifreleme, hash'leme, imzalama gibi birçok işlev sunar.
    ```bash
    # Örnek: Kendinden imzalı bir sertifika oluşturma
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes

    # Örnek: Bir dosyanın SHA256 hash'ini hesaplama
    openssl dgst -sha256 filename.txt
    ```
-   **GnuPG (GPG):** OpenPGP standardının ücretsiz bir uygulamasıdır. Dosyaları ve e-postaları şifrelemek ve imzalamak için kullanılır.
    ```bash
    # Örnek: Bir dosya şifreleme
    gpg -c filename.txt # Simetrik şifreleme
    gpg -e -r recipient@example.com filename.txt # Asimetrik şifreleme

    # Örnek: Bir dosyayı imzalama
    gpg --sign filename.txt
    ```
-   **Libgcrypt:** GnuPG tarafından kullanılan genel amaçlı bir kriptografi kütüphanesidir.
-   **Bouncy Castle:** Java ve C# için kapsamlı bir kriptografi API'si ve kütüphanesi.
-   **Cryptsetup (Linux):** LUKS kullanarak disk şifrelemesi için bir araç.
-   **VeraCrypt:** Windows, macOS ve Linux için açık kaynaklı disk şifreleme yazılımı (TrueCrypt'in devamı).
-   **Hashcat / John the Ripper:** Parola kırma ve hash analizi araçları (kriptanaliz amaçlı).
-   **Wireshark:** Ağ trafiğini analiz ederek SSL/TLS el sıkışmalarını ve şifreli trafiği incelemek için kullanılabilir (anahtarlar mevcutsa).

### Programlama Dillerinde Kriptografi Kütüphaneleri

-   **Python:** `cryptography`, `PyCryptodome`, `hashlib`
    ```python
    import hashlib
    # Bir string'in SHA256 hash'ini hesaplama
    text = "Merhaba Dünya"
    hashed_text = hashlib.sha256(text.encode('utf-8')).hexdigest()
    print(f"SHA256: {hashed_text}")
    ```
-   **Java:** Java Cryptography Architecture (JCA), Java Cryptography Extension (JCE)
-   **JavaScript (Node.js):** `crypto` modülü
-   **Go:** `crypto/...` paketleri (örn: `crypto/aes`, `crypto/rsa`)
-   **C/C++:** OpenSSL, Libsodium

---

## 7. En İyi Uygulamalar ve Güvenlik Hususları

-   **Güçlü ve Test Edilmiş Algoritmalar Kullanın:** Kendi kriptografik algoritmalarınızı tasarlamaktan kaçının ("Don't roll your own crypto"). Standartlaşmış, iyi incelenmiş ve güvenli kabul edilen algoritmaları (örn: AES, RSA, SHA-256) tercih edin.
-   **Anahtar Yönetimi:**
    -   Anahtarları güvenli bir şekilde oluşturun, saklayın, dağıtın ve imha edin.
    -   Anahtar uzunlukları güncel güvenlik standartlarına uygun olmalıdır (örn: AES için en az 128-bit, RSA için en az 2048-bit).
    -   Anahtarları düzenli olarak değiştirin (key rotation).
    -   Donanım Güvenlik Modülleri (HSM - Hardware Security Module) gibi özel donanımlar kullanarak anahtarların güvenliğini artırın.
-   **Rastgelelik (Randomness):** Kriptografik anahtarların ve diğer parametrelerin (örn: IV, nonce) üretiminde kriptografik olarak güvenli rastgele sayı üreteçleri (CSPRNG - Cryptographically Secure Pseudo-Random Number Generator) kullanın.
-   **Tuzlama (Salting) ve Biberleme (Peppering):** Parola hash'lerini saklarken, her parola için benzersiz bir "tuz" (salt) ekleyin ve genel bir "biber" (pepper) kullanarak gökkuşağı tabloları (rainbow tables) ve kaba kuvvet saldırılarına karşı direnci artırın.
-   **Doğru Modları Kullanın:** Blok şifreler için ECB gibi güvensiz modlardan kaçının; CBC, CTR veya GCM gibi güvenli modları tercih edin.
-   **Sertifika Yönetimi:** PKI kullanıyorsanız, sertifikaların geçerliliğini düzenli olarak kontrol edin, CRL/OCSP mekanizmalarını doğru şekilde uygulayın ve güvenilir CA'lar kullanın.
-   **Yan Kanal Saldırılarına (Side-Channel Attacks) Dikkat Edin:** Kriptografik sistemlerin fiziksel uygulamalarından sızan bilgilere (örn: güç tüketimi, zamanlama bilgisi, elektromanyetik radyasyon) dayanan saldırılara karşı önlemler alın.
-   **Kuantum Sonrası Kriptografi (Post-Quantum Cryptography - PQC):** Gelecekte kuantum bilgisayarların mevcut birçok asimetrik şifreleme algoritmasını kırabileceği öngörülmektedir. Bu tehdide karşı PQC algoritmaları geliştirilmektedir ve gelecekteki sistemlerde kullanılması planlanmaktadır.
-   **Güvenlik Güncellemeleri:** Kullandığınız kriptografi kütüphanelerini ve araçlarını düzenli olarak güncelleyin.

---

## 8. Zorluklar ve Sınırlamalar

-   **İnsan Faktörü:** En güçlü kriptografi bile yanlış uygulamalar, zayıf parolalar veya sosyal mühendislik nedeniyle etkisiz hale gelebilir.
-   **Anahtar Yönetimi Karmaşıklığı:** Özellikle büyük ölçekli sistemlerde güvenli ve verimli anahtar yönetimi zordur.
-   **Performans Maliyeti:** Güçlü şifreleme, özellikle kaynak kısıtlı cihazlarda performans düşüşlerine neden olabilir.
-   **Uygulama Hataları:** Kriptografik protokollerin veya algoritmaların yanlış uygulanması ciddi güvenlik açıklarına yol açabilir.
-   **Geriye Dönük Uyumluluk:** Eski sistemlerle uyumluluk sağlamak için bazen daha zayıf kriptografik standartların kullanılması gerekebilir.
-   **Kuantum Bilgisayar Tehdidi:** Gelecekteki güçlü kuantum bilgisayarlar, günümüzde kullanılan birçok asimetrik şifreleme algoritmasını (RSA, ECC) kırabilir.
-   **Yasal ve Etik Meseleler:** Şifrelemenin yaygın kullanımı, kolluk kuvvetlerinin yasal soruşturmalarını zorlaştırabilir (going dark problemi). Bazı ülkelerde şifreleme kullanımıyla ilgili kısıtlamalar veya zorunluluklar (arka kapılar) bulunabilir.

---

## 9. Gelecek Trendler

-   **Kuantum Sonrası Kriptografi (PQC):** Kuantum bilgisayarlara dayanıklı yeni kriptografik algoritmaların geliştirilmesi ve standartlaştırılması (örn: kafes tabanlı, kod tabanlı, çok değişkenli, hash tabanlı imzalar).
-   **Homomorfik Şifreleme (Homomorphic Encryption):** Verilerin şifreliyken üzerinde hesaplama yapılmasına olanak tanıyan bir şifreleme türü. Veri gizliliğini korurken bulut bilişim gibi alanlarda analiz yapılmasını sağlar.
-   **Tamamen Güvenli Çok Taraflı Hesaplama (Secure Multi-Party Computation - MPC):** Birden fazla tarafın, birbirlerinin özel girdilerini ifşa etmeden, bu girdiler üzerinde ortak bir fonksiyonu hesaplamasına olanak tanır.
-   **Blokzincir ve Kriptografi:** Blokzincir teknolojilerinin güvenliği ve işlevselliği için kriptografinin daha da entegre olması.
-   **Hafif Kriptografi (Lightweight Cryptography):** IoT cihazları ve diğer kaynak kısıtlı ortamlar için optimize edilmiş, düşük enerji ve işlem gücü tüketen kriptografik algoritmalar.
-   **Yapay Zeka ve Kriptografi:** Yapay zekanın kriptanalizde veya yeni kriptografik sistemlerin tasarımında kullanılması.
-   **Gizlilik Artırıcı Teknolojiler (PET - Privacy-Enhancing Technologies):** Sıfır bilgi kanıtları (Zero-Knowledge Proofs) gibi tekniklerin daha yaygın kullanımı.

---

## 10. Kaynaklar ve Referanslar

### 📖 Önerilen Kitaplar

-   "Cryptography Engineering: Design Principles and Practical Applications" - Niels Ferguson, Bruce Schneier, Tadayoshi Kohno
-   "Introduction to Modern Cryptography" - Jonathan Katz, Yehuda Lindell
-   "Serious Cryptography: A Practical Introduction to Modern Encryption" - Jean-Philippe Aumasson
-   "Understanding Cryptography: A Textbook for Students and Practitioners" - Christof Paar, Jan Pelzl
-   "Applied Cryptography: Protocols, Algorithms, and Source Code in C" - Bruce Schneier

### 🌐 Online Kaynaklar ve Kurslar

-   **Coursera / Stanford University:** [Cryptography I](https://www.coursera.org/learn/crypto)
-   **Coursera / University of Maryland:** [Cryptography](https://www.coursera.org/specializations/cryptography)
-   **CryptoHack:** Kriptografi öğrenmek için eğlenceli, pratik zorluklar sunan bir platform.
-   **NIST Cryptographic Standards and Guidelines:** <mcurl name="NIST CSRC" url="https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines"></mcurl>
-   **IACR (International Association for Cryptologic Research):** <mcurl name="IACR" url="https://www.iacr.org/"></mcurl> (Kriptoloji alanındaki yayınlar ve konferanslar)

### 🛠️ Araçlar

-   <mcurl name="OpenSSL" url="https://www.openssl.org/"></mcurl>
-   <mcurl name="GnuPG" url="https://gnupg.org/"></mcurl>
-   <mcurl name="VeraCrypt" url="https://www.veracrypt.fr/"></mcurl>

---

## ✅ Seviye 1 - Kriptografi Temelleri Tamamlama Kriterleri

### 📋 Teorik Bilgi

-   [ ] Simetrik ve asimetrik şifreleme arasındaki farkları açıklayabilme.
-   [ ] Yaygın simetrik (AES) ve asimetrik (RSA, ECC) algoritmaların temel çalışma prensiplerini bilme.
-   [ ] Hash fonksiyonlarının (SHA-256) ne olduğunu ve ne için kullanıldığını anlama.
-   [ ] Dijital imzaların ve MAC'lerin amacını ve işleyişini kavrama.
-   [ ] PKI'nın temel bileşenlerini ve amacını açıklayabilme.
-   [ ] Kriptografinin temel güvenlik hedeflerini (gizlilik, bütünlük, kimlik doğrulama) sayabilme.

### 🛠️ Pratik Beceriler

-   [ ] OpenSSL veya GnuPG kullanarak basit şifreleme/deşifreleme işlemleri yapabilme.
-   [ ] Bir dosyanın hash değerini hesaplayabilme.
-   [ ] Kendinden imzalı bir dijital sertifika oluşturma adımlarını bilme (teorik olarak).
-   [ ] Güvenli parola saklama yöntemlerinde tuzlama (salting) kavramını açıklayabilme.

### 🔗 Bağlantılı Konular

Bu bölümdeki bilgiler, aşağıdaki konularla yakından ilişkilidir:

-   <mcfile name="network-security.md" path="/Users/ibrahim/CyberSecuirty101-RoadMap/level-1/network-security.md"></mcfile> (SSL/TLS, VPN)
-   <mcfile name="owasp-top10.md" path="/Users/ibrahim/CyberSecuirty101-RoadMap/level-1/owasp-top10.md"></mcfile> (A02: Cryptographic Failures)
-   <mcfile name="system-security.md" path="/Users/ibrahim/CyberSecuirty101-RoadMap/level-1/system-security.md"></mcfile> (Disk şifreleme, parola güvenliği)

---

**Sonraki Konu**: Seviye 1 tamamlandı. [Seviye 2 - Penetrasyon Testi Temelleri](../level-2/penetration-testing-basics.md) (Bu dosya henüz oluşturulmadı)

*Bu doküman siber güvenlik yol haritasının bir parçasıdır. Katkıda bulunmak veya en son sürümü görmek için ana repoyu ziyaret edin.*