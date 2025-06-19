#!/usr/bin/env python3
"""
Cryptography Examples
Author: ibrahimsql
Description: Examples demonstrating cryptography fundamentals
"""

import hashlib
import hmac
import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os
from typing import Tuple, Dict, Any

class CryptographyExamples:
    """Cryptography examples class"""
    
    @staticmethod
    def hash_examples():
        """Hash function examples"""
        text = "Hello World"
        
        # SHA256 hash calculation
        sha256_hash = hashlib.sha256(text.encode('utf-8')).hexdigest()
        
        # Other hash algorithms
        md5_hash = hashlib.md5(text.encode('utf-8')).hexdigest()
        sha1_hash = hashlib.sha1(text.encode('utf-8')).hexdigest()
        sha512_hash = hashlib.sha512(text.encode('utf-8')).hexdigest()
        
        print("🔐 Hash Function Examples:")
        print(f"Original Text: {text}")
        print(f"MD5: {md5_hash}")
        print(f"SHA1: {sha1_hash}")
        print(f"SHA256: {sha256_hash}")
        print(f"SHA512: {sha512_hash}")
        
        return {
            'md5': md5_hash,
            'sha1': sha1_hash,
            'sha256': sha256_hash,
            'sha512': sha512_hash
        }
    
    @staticmethod
    def password_hashing_examples():
        """Secure password hashing examples"""
        password = "MySecurePassword123!"
        
        print("\n🔒 Password Hashing Examples:")
        print(f"Original Password: {password}")
        
        # 1. Simple SHA256 (INSECURE)
        simple_hash = hashlib.sha256(password.encode()).hexdigest()
        print(f"\n❌ Simple SHA256 (INSECURE): {simple_hash}")
        
        # 2. SHA256 + Salt (Better)
        salt = secrets.token_hex(16)
        salted_password = password + salt
        salted_hash = hashlib.sha256(salted_password.encode()).hexdigest()
        print(f"\n✅ SHA256 + Salt:")
        print(f"Salt: {salt}")
        print(f"Hash: {salted_hash}")
        
        # 3. PBKDF2 (Recommended)
        salt_pbkdf2 = os.urandom(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_pbkdf2,
            iterations=100000,
        )
        pbkdf2_hash = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        print(f"\n✅ PBKDF2 (RECOMMENDED):")
        print(f"Salt: {base64.urlsafe_b64encode(salt_pbkdf2).decode()}")
        print(f"Hash: {pbkdf2_hash.decode()}")
        
        # 4. Scrypt (Very secure)
        salt_scrypt = os.urandom(32)
        kdf_scrypt = Scrypt(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_scrypt,
            n=2**14,
            r=8,
            p=1,
        )
        scrypt_hash = base64.urlsafe_b64encode(kdf_scrypt.derive(password.encode()))
        print(f"\n✅ Scrypt (VERY SECURE):")
        print(f"Salt: {base64.urlsafe_b64encode(salt_scrypt).decode()}")
        print(f"Hash: {scrypt_hash.decode()}")
        
        return {
            'simple': simple_hash,
            'salted': {'hash': salted_hash, 'salt': salt},
            'pbkdf2': {'hash': pbkdf2_hash.decode(), 'salt': base64.urlsafe_b64encode(salt_pbkdf2).decode()},
            'scrypt': {'hash': scrypt_hash.decode(), 'salt': base64.urlsafe_b64encode(salt_scrypt).decode()}
        }
    
    @staticmethod
    def symmetric_encryption_examples():
        """Symmetric encryption examples"""
        plaintext = "This is a very secret message!"
        
        print("\n🔐 Symmetric Encryption Examples:")
        print(f"Original Text: {plaintext}")
        
        # 1. Fernet (Simple and secure)
        key_fernet = Fernet.generate_key()
        fernet = Fernet(key_fernet)
        encrypted_fernet = fernet.encrypt(plaintext.encode())
        decrypted_fernet = fernet.decrypt(encrypted_fernet).decode()
        
        print(f"\n✅ Fernet Encryption:")
        print(f"Key: {key_fernet.decode()}")
        print(f"Encrypted: {encrypted_fernet}")
        print(f"Decrypted: {decrypted_fernet}")
        
        # 2. AES-256-CBC
        key_aes = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)       # 128-bit IV
        
        cipher = Cipher(algorithms.AES(key_aes), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Padding (PKCS7)
        padded_data = CryptographyExamples._pad_pkcs7(plaintext.encode(), 16)
        encrypted_aes = encryptor.update(padded_data) + encryptor.finalize()
        
        # Decryption
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_aes) + decryptor.finalize()
        decrypted_aes = CryptographyExamples._unpad_pkcs7(decrypted_padded).decode()
        
        print(f"\n✅ AES-256-CBC:")
        print(f"Key: {base64.b64encode(key_aes).decode()}")
        print(f"IV: {base64.b64encode(iv).decode()}")
        print(f"Encrypted: {base64.b64encode(encrypted_aes).decode()}")
        print(f"Decrypted: {decrypted_aes}")
        
        # 3. AES-256-GCM (Authenticated Encryption)
        key_gcm = os.urandom(32)
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        
        cipher_gcm = Cipher(algorithms.AES(key_gcm), modes.GCM(nonce))
        encryptor_gcm = cipher_gcm.encryptor()
        encrypted_gcm = encryptor_gcm.update(plaintext.encode()) + encryptor_gcm.finalize()
        tag = encryptor_gcm.tag
        
        # Decryption
        decryptor_gcm = Cipher(algorithms.AES(key_gcm), modes.GCM(nonce, tag)).decryptor()
        decrypted_gcm = decryptor_gcm.update(encrypted_gcm) + decryptor_gcm.finalize()
        
        print(f"\n✅ AES-256-GCM (Authenticated):")
        print(f"Key: {base64.b64encode(key_gcm).decode()}")
        print(f"Nonce: {base64.b64encode(nonce).decode()}")
        print(f"Tag: {base64.b64encode(tag).decode()}")
        print(f"Encrypted: {base64.b64encode(encrypted_gcm).decode()}")
        print(f"Decrypted: {decrypted_gcm.decode()}")
        
        return {
            'fernet': {'key': key_fernet.decode(), 'encrypted': encrypted_fernet, 'decrypted': decrypted_fernet},
            'aes_cbc': {'key': base64.b64encode(key_aes).decode(), 'encrypted': base64.b64encode(encrypted_aes).decode()},
            'aes_gcm': {'key': base64.b64encode(key_gcm).decode(), 'encrypted': base64.b64encode(encrypted_gcm).decode()}
        }
    
    @staticmethod
    def asymmetric_encryption_examples():
        """Asymmetric encryption examples"""
        plaintext = "Asymmetric encryption example"
        
        print("\n🔐 Asymmetric Encryption Examples:")
        print(f"Original Text: {plaintext}")
        
        # RSA key pair generation
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        
        # Encryption with public key
        encrypted = public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decryption with private key
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Serialize keys in PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        print(f"\n✅ RSA-2048 Encryption:")
        print(f"Public Key:\n{public_pem.decode()}")
        print(f"Encrypted: {base64.b64encode(encrypted).decode()}")
        print(f"Decrypted: {decrypted.decode()}")
        
        return {
            'public_key': public_pem.decode(),
            'private_key': private_pem.decode(),
            'encrypted': base64.b64encode(encrypted).decode(),
            'decrypted': decrypted.decode()
        }
    
    @staticmethod
    def digital_signature_examples():
        """Dijital imza örnekleri"""
        message = "The integrity of this message is protected by digital signature."
        
        print("\n✍️ Digital Signature Examples:")
        print(f"Original Message: {message}")
        
        # RSA key pair generation
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        
        # Dijital imza oluşturma
        signature = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Signature verification
        try:
            public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            signature_valid = True
        except Exception:
            signature_valid = False
        
        print(f"\n✅ RSA Digital Signature:")
        print(f"Signature: {base64.b64encode(signature).decode()}")
        print(f"Signature Valid: {signature_valid}")
        
        # Mesaj değiştirilirse imza geçersiz olur
        tampered_message = "This message has been tampered!"
        try:
            public_key.verify(
                signature,
                tampered_message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            tampered_valid = True
        except Exception:
            tampered_valid = False
        
        print(f"\n❌ Tampered Message Verification:")
        print(f"Tampered Message: {tampered_message}")
        print(f"Signature Valid: {tampered_valid}")
        
        return {
            'original_message': message,
            'signature': base64.b64encode(signature).decode(),
            'signature_valid': signature_valid,
            'tampered_message': tampered_message,
            'tampered_valid': tampered_valid
        }
    
    @staticmethod
    def hmac_examples():
        """HMAC examples"""
        message = "The integrity of this message is protected by HMAC."
        secret_key = secrets.token_bytes(32)
        
        print("\n🔐 HMAC Examples:")
        print(f"Message: {message}")
        print(f"Secret Key: {base64.b64encode(secret_key).decode()}")
        
        # HMAC-SHA256
        hmac_sha256 = hmac.new(
            secret_key,
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # HMAC-SHA512
        hmac_sha512 = hmac.new(
            secret_key,
            message.encode(),
            hashlib.sha512
        ).hexdigest()
        
        print(f"\n✅ HMAC Results:")
        print(f"HMAC-SHA256: {hmac_sha256}")
        print(f"HMAC-SHA512: {hmac_sha512}")
        
        # HMAC verification
        def verify_hmac(message, key, received_hmac, algorithm=hashlib.sha256):
            expected_hmac = hmac.new(key, message.encode(), algorithm).hexdigest()
            return hmac.compare_digest(expected_hmac, received_hmac)
        
        # Correct HMAC
        is_valid = verify_hmac(message, secret_key, hmac_sha256)
        print(f"\n✅ HMAC Verification (Correct): {is_valid}")
        
        # Wrong HMAC
        wrong_hmac = "wrong_hmac_value"
        is_invalid = verify_hmac(message, secret_key, wrong_hmac)
        print(f"❌ HMAC Verification (Wrong): {is_invalid}")
        
        return {
            'message': message,
            'hmac_sha256': hmac_sha256,
            'hmac_sha512': hmac_sha512,
            'verification_correct': is_valid,
            'verification_wrong': is_invalid
        }
    
    @staticmethod
    def key_derivation_examples():
        """Key derivation examples"""
        password = "UserPassword123!"
        
        print("\n🔑 Key Derivation Examples:")
        print(f"Password: {password}")
        
        # PBKDF2
        salt_pbkdf2 = os.urandom(32)
        kdf_pbkdf2 = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_pbkdf2,
            iterations=100000,
        )
        key_pbkdf2 = kdf_pbkdf2.derive(password.encode())
        
        print(f"\n✅ PBKDF2:")
        print(f"Salt: {base64.b64encode(salt_pbkdf2).decode()}")
        print(f"Iterations: 100,000")
        print(f"Derived Key: {base64.b64encode(key_pbkdf2).decode()}")
        
        # Scrypt
        salt_scrypt = os.urandom(32)
        kdf_scrypt = Scrypt(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_scrypt,
            n=2**14,  # CPU/Memory cost
            r=8,      # Block size
            p=1,      # Parallelization
        )
        key_scrypt = kdf_scrypt.derive(password.encode())
        
        print(f"\n✅ Scrypt:")
        print(f"Salt: {base64.b64encode(salt_scrypt).decode()}")
        print(f"N: {2**14}, R: 8, P: 1")
        print(f"Derived Key: {base64.b64encode(key_scrypt).decode()}")
        
        return {
            'pbkdf2': {
                'salt': base64.b64encode(salt_pbkdf2).decode(),
                'key': base64.b64encode(key_pbkdf2).decode()
            },
            'scrypt': {
                'salt': base64.b64encode(salt_scrypt).decode(),
                'key': base64.b64encode(key_scrypt).decode()
            }
        }
    
    @staticmethod
    def _pad_pkcs7(data: bytes, block_size: int) -> bytes:
        """PKCS7 padding"""
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def _unpad_pkcs7(data: bytes) -> bytes:
        """PKCS7 padding removal"""
        padding_length = data[-1]
        return data[:-padding_length]
    
    @staticmethod
    def cryptographic_best_practices():
        """Cryptographic best practices"""
        practices = {
            "Key Management": [
                "Use strong random keys",
                "Store keys securely",
                "Perform regular key rotation",
                "Use HSM (Hardware Security Module)"
            ],
            "Algorithm Selection": [
                "Use tested and standard algorithms",
                "Don't write your own cryptographic algorithms",
                "Follow current security standards",
                "Don't use deprecated algorithms"
            ],
            "Implementation Security": [
                "Protect against timing attacks",
                "Consider side-channel attacks",
                "Use secure random number generator",
                "Use proper padding and modes"
            ],
            "Password Security": [
                "Use salt",
                "Use sufficient iteration count",
                "Use strong hash functions",
                "Consider using pepper"
            ]
        }
        
        print("\n📋 Cryptographic Best Practices:")
        for category, items in practices.items():
            print(f"\n{category}:")
            for item in items:
                print(f"  • {item}")
        
        return practices

# Kullanım örnekleri
if __name__ == "__main__":
    crypto = CryptographyExamples()
    
    print("🔐 CRYPTOGRAPHY EXAMPLES DEMONSTRATION")
    print("=" * 50)
    
    # Hash examples
    hash_results = crypto.hash_examples()

    # Password hashing
    password_results = crypto.password_hashing_examples()

    # Symmetric encryption
    symmetric_results = crypto.symmetric_encryption_examples()

    # Asymmetric encryption
    asymmetric_results = crypto.asymmetric_encryption_examples()

    # Digital signature
    signature_results = crypto.digital_signature_examples()

    # HMAC
    hmac_results = crypto.hmac_examples()

    # Key derivation
    kdf_results = crypto.key_derivation_examples()

    # Best practices
    best_practices = crypto.cryptographic_best_practices()
    
    print("\n✅ Cryptography examples completed!")
    print("🔒 Remember: Use these examples for educational purposes and follow best practices!")