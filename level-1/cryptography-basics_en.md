# 🔐 Level 1 - Cryptography Basics

## 🎯 Level Objective

In this section, you will learn the fundamental concepts of cryptography, its history, modern cryptographic algorithms, and its critical role in cybersecurity. The focus will be on essential topics such as symmetric and asymmetric encryption, hash functions, digital signatures, and Public Key Infrastructure (PKI).

## 📚 Topics

1. [Executive Summary](#1-executive-summary)
2. [Introduction: What is Cryptography?](#2-introduction-what-is-cryptography)
3. [Basic Concepts and Terminology](#3-basic-concepts-and-terminology)
4. [Key Algorithms and Techniques](#4-key-algorithms-and-techniques)
5. [Practical Applications and Use Cases](#5-practical-applications-and-use-cases)
6. [Tools and Technologies](#6-tools-and-technologies)
7. [Best Practices and Security Considerations](#7-best-practices-and-security-considerations)
8. [Challenges and Limitations](#8-challenges-and-limitations)
9. [Future Trends](#9-future-trends)
10. [Resources and References](#10-resources-and-references)

---

## 1. Executive Summary

Cryptography is the science and art of mathematical techniques used to protect information from unauthorized access. In today's digital world, it is an indispensable element for data confidentiality, integrity, and authentication. This section comprehensively covers the fundamental building blocks of cryptography, its modern applications, and its importance in cybersecurity.

---

## 2. Introduction: What is Cryptography?

Cryptography (from Greek "kryptos" - hidden and "graphein" - to write) studies methods of transforming readable information (plaintext) into an incomprehensible form (ciphertext) and reversing this process. Its primary purpose is to ensure communication confidentiality, data integrity, authentication of sender and receiver identities, and non-repudiation of transactions.

### History of Cryptography

- **Ancient Times:** Simple substitution ciphers like Caesar cipher.
- **Middle Ages and Renaissance:** Polyalphabetic ciphers (Vigenère cipher).
- **World Wars:** Mechanical encryption devices like the Enigma machine.
- **Modern Era:** Development of strong algorithms like DES, AES, RSA with the widespread adoption of computers and the internet.

### Role of Cryptography in Cybersecurity

- **Confidentiality:** Prevents unauthorized reading of data (e.g., HTTPS, SSL/TLS).
- **Integrity:** Checks whether data has been modified during transmission (e.g., Hash functions, MAC).
- **Authentication:** Verifies the identity of users or systems (e.g., Digital certificates, passwords).
- **Non-repudiation:** Prevents denial of performing an action or sending a message (e.g., Digital signatures).

---

## 3. Basic Concepts and Terminology

- **Plaintext:** Unencrypted, readable original message.
- **Ciphertext:** Incomprehensible message transformed by applying an encryption algorithm.
- **Encryption:** Process of converting plaintext to ciphertext.
- **Decryption:** Process of converting ciphertext back to plaintext.
- **Key:** Secret piece of information that controls encryption and decryption operations.
- **Algorithm (Cipher/Algorithm):** Set of mathematical rules used for encryption and decryption.
- **Cryptanalysis:** Science of breaking ciphertext without knowing the key or finding weaknesses in encryption systems.
- **Cryptology:** General science that encompasses both cryptography and cryptanalysis.

### Security Goals (CIA Triad and Beyond)

- **Confidentiality:** Only authorized individuals can access information.
- **Integrity:** Protection of information against unauthorized modification.
- **Availability:** Authorized users can access information and resources when needed.
- **Authentication:** Verification that an entity (user, system) is who they claim to be.
- **Authorization:** Determining what resources an authenticated identity has access to.
- **Non-repudiation:** Proving that an action or event occurred, preventing the perpetrator from denying it.

---

## 4. Key Algorithms and Techniques

### a. Symmetric Encryption (Secret Key Cryptography)

A method where the same key is used for both encryption and decryption. It is fast but key distribution must be done securely.

- **Block Ciphers:** Divides data into fixed-size blocks and encrypts each block separately.
  - **DES (Data Encryption Standard):** An old standard, now considered insecure (56-bit key).
  - **3DES (Triple DES):** Applies DES three times to increase security, but is slow.
  - **AES (Advanced Encryption Standard):** Currently widely used secure standard (128, 192, 256-bit keys).
    - Operating Modes: ECB, CBC, CFB, OFB, CTR.
- **Stream Ciphers:** Encrypts data bit by bit or byte by byte.
  - **RC4:** Previously used in SSL/TLS and WEP, but no longer recommended due to vulnerabilities.
  - **ChaCha20:** Modern and secure stream cipher, often used with Poly1305.

**Advantages:** Fast, requires less processing power.
**Disadvantages:** Key distribution is difficult and risky. Too many keys needed for many users.

### b. Asymmetric Encryption (Public Key Cryptography)

Uses two different but mathematically related keys for encryption and decryption: public key and private key.

- **Public Key:** Can be shared with everyone, used to encrypt messages or verify digital signatures.
- **Private Key:** Known only by the owner, used to decrypt encrypted messages or create digital signatures.

- **RSA (Rivest-Shamir-Adleman):** Most widely used asymmetric algorithm. Based on the difficulty of factoring large numbers.
- **ECC (Elliptic Curve Cryptography):** Based on mathematical operations over elliptic curves. Provides the same level of security as RSA with shorter key lengths, making it ideal for mobile and IoT devices.
- **Diffie-Hellman Key Exchange:** Allows two parties to create a common secret key over an insecure channel. Used for key exchange, not encryption.
- **ElGamal:** Another asymmetric encryption and digital signature algorithm based on the difficulty of the discrete logarithm problem.

**Advantages:** Secure key distribution, provides digital signatures and authentication.
**Disadvantages:** Slower than symmetric encryption, requires more computational resources.

### c. Hash Functions (Digest Functions)

One-way mathematical functions that transform variable-length input (message) into fixed-length unique output (hash value or message digest). The same input always produces the same output, but obtaining the input from the output is computationally impossible (or very difficult).

- **Properties:**
  - **One-way:** Cannot reverse from hash value to original message.
  - **Collision Resistance:** Very difficult for two different inputs to produce the same hash value.
    - *Weak Collision Resistance:* Hard to find a y such that H(x) = H(y) for a given x.
    - *Strong Collision Resistance:* Hard to find any (x, y) pair such that H(x) = H(y).
  - **Deterministic:** Same message always produces the same hash value.
  - **Avalanche Effect:** Small change in input causes large change in output.

- **Common Algorithms:**
  - **MD5 (Message Digest 5):** Now considered insecure, has collision vulnerabilities (128-bit).
  - **SHA-1 (Secure Hash Algorithm 1):** Considered insecure, has collision vulnerabilities (160-bit).
  - **SHA-2 Family (SHA-224, SHA-256, SHA-384, SHA-512):** Currently widely used secure standards.
  - **SHA-3 Family (Keccak):** New generation standard with different design from SHA-2.
  - **BLAKE2/BLAKE3:** Fast and secure modern hash functions.

**Use Cases:** Data integrity checking, password storage, digital signatures, blockchain.

### d. Digital Signatures

A mechanism that uses asymmetric cryptography to verify the integrity of a message or document and the identity of its sender. The sender signs the message with their private key; the receiver verifies the signature using the sender's public key.

- **Process:**
  1. Sender calculates the hash value of the message.
  2. Encrypts the calculated hash value with their private key (this is the digital signature).
  3. Sends the original message and digital signature to the receiver.
  4. Receiver decrypts the digital signature using the sender's public key (obtains the original hash value).
  5. Receiver also calculates the hash value of the received original message.
  6. Compares the two hash values. If they match, the message integrity and sender identity are verified.

- **Algorithms:** RSA, DSA (Digital Signature Algorithm), ECDSA (Elliptic Curve Digital Signature Algorithm).

### e. Message Authentication Codes (MAC)

A short piece of information based on a shared secret key used to verify both the integrity and authenticity of a message. Similar to hash functions but includes a secret key.

- **HMAC (Hash-based MAC):** Uses a hash function (e.g., SHA-256) and a secret key. Example: HMAC-SHA256.
- **CMAC (Cipher-based MAC):** Uses a block encryption algorithm (e.g., AES) and a secret key.

**Difference:** Digital signatures use public key cryptography while MACs use symmetric (secret) keys. Therefore, MACs require a pre-shared secret key between parties and do not provide non-repudiation.

### f. Public Key Infrastructure (PKI)

The complete set of roles, policies, hardware, software, and procedures needed to create, manage, distribute, use, store, and revoke digital certificates. Its main purpose is to securely bind public keys to specific identities.

- **Components:**
  - **Certificate Authority (CA):** Trusted third party that issues and validates digital certificates (e.g., Let's Encrypt, DigiCert, Comodo).
  - **Registration Authority (RA):** Performs identity verification processes on behalf of the CA.
  - **Digital Certificate:** Electronic document that associates a public key with an identity (person, server, company). X.509 standard is widely used.
    - Contents: Owner's name, public key, CA's name, validity period, serial number, CA's digital signature.
  - **Certificate Revocation List (CRL):** List of certificates that are no longer valid (compromised, revoked before expiration).
  - **Online Certificate Status Protocol (OCSP):** Protocol used to query the validity status of a certificate in real-time.
  - **Certificate Repository:** Where published certificates and CRLs are stored.

---

## 5. Practical Applications and Use Cases

- **Secure Web Communication (HTTPS):** SSL/TLS protocols use asymmetric and symmetric cryptography with digital certificates to establish encrypted connections between web servers and browsers.
- **Email Security:**
  - **PGP (Pretty Good Privacy) / GPG (GNU Privacy Guard):** Used to encrypt and sign emails.
  - **S/MIME (Secure/Multipurpose Internet Mail Extensions):** Uses X.509 certificates to add digital signatures and encryption to emails.
- **Data Storage Security (Data at Rest):**
  - **Full Disk Encryption (FDE):** Encrypts entire hard disk with tools like BitLocker (Windows), FileVault (macOS), LUKS (Linux).
  - **File/Folder Encryption:** Used to encrypt specific files or folders (e.g., VeraCrypt, AxCrypt).
  - **Database Encryption:** Used to protect sensitive data in databases.
- **Virtual Private Networks (VPN):** Creates encrypted tunnels to provide secure access to private networks over insecure networks (e.g., internet) (IPSec, OpenVPN).
- **Wireless Network Security:** WPA2/WPA3 protocols use algorithms like AES to encrypt wireless network traffic.
- **Digital Currencies (Cryptocurrencies):** Cryptocurrencies like Bitcoin and Ethereum extensively use cryptographic techniques such as hash functions and digital signatures to secure transactions, create new units, and verify ownership (Blockchain technology).
- **Identity Management and Access Control:** Password hashing, smart cards, biometric systems.
- **Software Security:** Code signing, used to verify the integrity of software updates.
- **Internet of Things (IoT) Security:** Lightweight cryptographic solutions for data confidentiality and integrity in resource-constrained IoT devices.

---

## 6. Tools and Technologies

- **OpenSSL:** Open-source implementation of SSL/TLS protocols and a general-purpose cryptography library. Offers many functions including certificate management, encryption, hashing, signing.
  ```bash
  # Example: Creating a self-signed certificate
  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes

  # Example: Calculating SHA256 hash of a file
  openssl dgst -sha256 filename.txt
  ```
- **GnuPG (GPG):** Free implementation of the OpenPGP standard. Used to encrypt and sign files and emails.
  ```bash
  # Example: File encryption
  gpg -c filename.txt # Symmetric encryption
  gpg -e -r recipient@example.com filename.txt # Asymmetric encryption

  # Example: Signing a file
  gpg --sign filename.txt
  ```
- **Libgcrypt:** General-purpose cryptography library used by GnuPG.
- **Cryptsetup (Linux):** Tool for disk encryption using LUKS.
- **VeraCrypt:** Open-source disk encryption software for Windows, macOS, and Linux (successor to TrueCrypt).
- **Hashcat / John the Ripper:** Password cracking and hash analysis tools (for cryptanalysis purposes).
- **Wireshark:** Can be used to analyze network traffic and examine SSL/TLS handshakes and encrypted traffic (if keys are available).

### Cryptography Libraries in Programming Languages

- **Python:** `cryptography`, `PyCryptodome`, `hashlib`
  ```python
  import hashlib
  # Calculating SHA256 hash of a string
  text = "Hello World"
  hashed_text = hashlib.sha256(text.encode('utf-8')).hexdigest()
  print(f"SHA256: {hashed_text}")
  ```
- **Java:** Java Cryptography Architecture (JCA), Java Cryptography Extension (JCE)
- **JavaScript (Node.js):** `crypto` module
- **Go:** `crypto/...` packages (e.g., `crypto/aes`, `crypto/rsa`)
- **C/C++:** OpenSSL, Libsodium

---

## 7. Best Practices and Security Considerations

- **Use Strong and Tested Algorithms:** Avoid designing your own cryptographic algorithms ("Don't roll your own crypto"). Prefer standardized, well-reviewed, and securely accepted algorithms (e.g., AES, RSA, SHA-256).
- **Key Management:**
  - Securely generate, store, distribute, and destroy keys.
  - Key lengths should comply with current security standards (e.g., at least 128-bit for AES, at least 2048-bit for RSA).
  - Regularly change keys (key rotation).
  - Enhance key security using specialized hardware like Hardware Security Modules (HSM).
- **Randomness:** Use cryptographically secure pseudo-random number generators (CSPRNG) for generating cryptographic keys and other parameters (e.g., IV, nonce).
- **Salting and Peppering:** When storing password hashes, add a unique "salt" for each password and use a general "pepper" to increase resistance against rainbow tables and brute force attacks.
- **Use Correct Modes:** For block ciphers, avoid insecure modes like ECB; prefer secure modes like CBC, CTR, or GCM.
- **Certificate Management:** If using PKI, regularly check certificate validity, properly implement CRL/OCSP mechanisms, and use trusted CAs.
- **Beware of Side-Channel Attacks:** Take measures against attacks based on information leaked from physical implementations of cryptographic systems (e.g., power consumption, timing information, electromagnetic radiation).
- **Post-Quantum Cryptography (PQC):** It is anticipated that future quantum computers may break many current asymmetric encryption algorithms. PQC algorithms are being developed against this threat and planned for use in future systems.
- **Security Updates:** Regularly update the cryptography libraries and tools you use.

---

## 8. Challenges and Limitations

- **Human Factor:** Even the strongest cryptography can become ineffective due to incorrect implementations, weak passwords, or social engineering.
- **Key Management Complexity:** Secure and efficient key management is difficult, especially in large-scale systems.
- **Performance Cost:** Strong encryption can cause performance degradation, especially on resource-constrained devices.
- **Implementation Errors:** Incorrect implementation of cryptographic protocols or algorithms can lead to serious security vulnerabilities.
- **Backward Compatibility:** Sometimes weaker cryptographic standards may need to be used to ensure compatibility with legacy systems.
- **Quantum Computer Threat:** Future powerful quantum computers may break many asymmetric encryption algorithms (RSA, ECC) currently in use.
- **Legal and Ethical Issues:** Widespread use of encryption can complicate law enforcement's legal investigations (going dark problem). Some countries may have restrictions or requirements (backdoors) regarding encryption use.

---

## 9. Future Trends

- **Post-Quantum Cryptography (PQC):** Development and standardization of new cryptographic algorithms resistant to quantum computers (e.g., lattice-based, code-based, multivariate, hash-based signatures).
- **Homomorphic Encryption:** A type of encryption that allows computation on data while it remains encrypted. Enables analysis in areas like cloud computing while preserving data privacy.
- **Secure Multi-Party Computation (MPC):** Allows multiple parties to compute a joint function over their inputs without revealing their private inputs to each other.
- **Blockchain and Cryptography:** Further integration of cryptography for the security and functionality of blockchain technologies.
- **Lightweight Cryptography:** Cryptographic algorithms optimized for IoT devices and other resource-constrained environments, consuming low energy and processing power.
- **Artificial Intelligence and Cryptography:** Use of artificial intelligence in cryptanalysis or design of new cryptographic systems.
- **Privacy-Enhancing Technologies (PET):** More widespread use of techniques like Zero-Knowledge Proofs.

---

## 10. Resources and References

### 📖 Recommended Books

- "Cryptography Engineering: Design Principles and Practical Applications" - Niels Ferguson, Bruce Schneier, Tadayoshi Kohno
- "Introduction to Modern Cryptography" - Jonathan Katz, Yehuda Lindell
- "Serious Cryptography: A Practical Introduction to Modern Encryption" - Jean-Philippe Aumasson
- "Understanding Cryptography: A Textbook for Students and Practitioners" - Christof Paar, Jan Pelzl
- "Applied Cryptography: Protocols, Algorithms, and Source Code in C" - Bruce Schneier

### 🌐 Online Resources and Courses

- **Coursera / Stanford University:** [Cryptography I](https://www.coursera.org/learn/crypto)
- **Coursera / University of Maryland:** [Cryptography](https://www.coursera.org/specializations/cryptography)
- **CryptoHack:** A platform offering fun, practical challenges for learning cryptography.
- **NIST Cryptographic Standards and Guidelines:** [NIST CSRC](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- **IACR (International Association for Cryptologic Research):** [IACR](https://www.iacr.org/) (Publications and conferences in cryptology)

### 🛠️ Tools

- [OpenSSL](https://www.openssl.org/)
- [GnuPG](https://gnupg.org/)
- [VeraCrypt](https://www.veracrypt.fr/)

---

## ✅ Level 1 - Cryptography Fundamentals Completion Criteria

### 📋 Theoretical Knowledge

- [ ] Ability to explain differences between symmetric and asymmetric encryption.
- [ ] Knowledge of basic working principles of common symmetric (AES) and asymmetric (RSA, ECC) algorithms.
- [ ] Understanding what hash functions (SHA-256) are and what they are used for.
- [ ] Grasping the purpose and operation of digital signatures and MACs.
- [ ] Ability to explain basic components and purpose of PKI.
- [ ] Ability to list basic security goals of cryptography (confidentiality, integrity, authentication).

### 🛠️ Practical Skills

- [ ] Ability to perform basic encryption/decryption operations using OpenSSL or GnuPG.
- [ ] Ability to calculate hash value of a file.
- [ ] Knowledge of steps to create a self-signed digital certificate (theoretically).
- [ ] Ability to explain the concept of salting in secure password storage methods.

### 🔗 Related Topics

The information in this section is closely related to the following topics:

- [Network Security](./network-security.md) (SSL/TLS, VPN)
- [OWASP Top 10](./owasp-top10.md) (A02: Cryptographic Failures)
- [System Security](./system-security.md) (Disk encryption, password security)

---

**Next Topic**: Level 1 completed. [Level 2 - Penetration Testing Fundamentals](../level-2/penetration-testing-basics.md) (This file has not been created yet)

*This document is part of the cybersecurity roadmap. Visit the main repository to contribute or see the latest version.*