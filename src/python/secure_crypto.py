#!/usr/bin/env python3
"""
Secure Cryptography Module
Author: ibrahimsql
Description: Güvenli kriptografi ve şifreleme işlemleri
"""

import secrets
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64
import os
from typing import Tuple, Optional

class SecureCrypto:
    """Güvenli kriptografi işlemleri sınıfı"""
    
    @staticmethod
    def hash_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Güvenli şifre hash'leme"""
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # PBKDF2 ile key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    @staticmethod
    def verify_password(password: str, hashed: bytes, salt: bytes) -> bool:
        """Şifre doğrulama"""
        key, _ = SecureCrypto.hash_password(password, salt)
        return secrets.compare_digest(key, hashed)
    
    @staticmethod
    def encrypt_data(data: str, key: bytes = None) -> Tuple[bytes, bytes]:
        """Veri şifreleme"""
        if key is None:
            key = Fernet.generate_key()
        
        f = Fernet(key)
        encrypted = f.encrypt(data.encode())
        return encrypted, key
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
        """Veri şifre çözme"""
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_data)
        return decrypted.decode()
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Güvenli token oluşturma"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """Güvenli şifre oluşturma"""
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def hash_file(file_path: str, algorithm: str = 'sha256') -> str:
        """Dosya hash'i hesaplama"""
        hash_algorithms = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }
        
        if algorithm not in hash_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        hasher = hash_algorithms[algorithm]
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    @staticmethod
    def generate_rsa_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
        """RSA anahtar çifti oluşturma"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        public_key = private_key.public_key()
        
        # Private key serialization
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Public key serialization
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    @staticmethod
    def rsa_encrypt(data: str, public_key_pem: bytes) -> bytes:
        """RSA ile şifreleme"""
        public_key = serialization.load_pem_public_key(public_key_pem)
        
        encrypted = public_key.encrypt(
            data.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return encrypted
    
    @staticmethod
    def rsa_decrypt(encrypted_data: bytes, private_key_pem: bytes) -> str:
        """RSA ile şifre çözme"""
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        
        decrypted = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted.decode()
    
    @staticmethod
    def aes_encrypt(data: str, key: bytes = None) -> Tuple[bytes, bytes, bytes]:
        """AES ile şifreleme"""
        if key is None:
            key = os.urandom(32)  # 256-bit key
        
        iv = os.urandom(16)  # 128-bit IV
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Padding
        data_bytes = data.encode()
        padding_length = 16 - (len(data_bytes) % 16)
        padded_data = data_bytes + bytes([padding_length] * padding_length)
        
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        return encrypted, key, iv
    
    @staticmethod
    def aes_decrypt(encrypted_data: bytes, key: bytes, iv: bytes) -> str:
        """AES ile şifre çözme"""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        padding_length = decrypted_padded[-1]
        decrypted = decrypted_padded[:-padding_length]
        
        return decrypted.decode()
    
    @staticmethod
    def secure_compare(a: str, b: str) -> bool:
        """Timing attack'a karşı güvenli string karşılaştırma"""
        return secrets.compare_digest(a.encode(), b.encode())
    
    @staticmethod
    def generate_hmac(message: str, key: bytes, algorithm: str = 'sha256') -> str:
        """HMAC oluşturma"""
        import hmac
        
        hash_algorithms = {
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'md5': hashlib.md5
        }
        
        if algorithm not in hash_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        return hmac.new(
            key,
            message.encode(),
            hash_algorithms[algorithm]
        ).hexdigest()
    
    @staticmethod
    def verify_hmac(message: str, signature: str, key: bytes, algorithm: str = 'sha256') -> bool:
        """HMAC doğrulama"""
        expected_signature = SecureCrypto.generate_hmac(message, key, algorithm)
        return secrets.compare_digest(signature, expected_signature)

class SecureStorage:
    """Güvenli veri saklama sınıfı"""
    
    def __init__(self, master_key: bytes = None):
        self.master_key = master_key or Fernet.generate_key()
        self.fernet = Fernet(self.master_key)
    
    def store_encrypted(self, data: str, filename: str) -> None:
        """Veriyi şifreleyerek dosyaya kaydet"""
        encrypted_data = self.fernet.encrypt(data.encode())
        
        with open(filename, 'wb') as f:
            f.write(encrypted_data)
    
    def load_encrypted(self, filename: str) -> str:
        """Şifrelenmiş veriyi dosyadan yükle"""
        with open(filename, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = self.fernet.decrypt(encrypted_data)
        return decrypted_data.decode()
    
    def get_master_key(self) -> bytes:
        """Master key'i al"""
        return self.master_key

# Kullanım örnekleri
if __name__ == "__main__":
    # Şifre hash'leme
    password = "user_password_123"
    hashed_password, salt = SecureCrypto.hash_password(password)
    print(f"Hashed password: {hashed_password}")
    print(f"Salt: {salt}")
    
    # Şifre doğrulama
    is_valid = SecureCrypto.verify_password(password, hashed_password, salt)
    print(f"Password valid: {is_valid}")
    
    # Veri şifreleme
    data = "Sensitive information"
    encrypted_data, key = SecureCrypto.encrypt_data(data)
    print(f"Encrypted: {encrypted_data}")
    
    # Veri şifre çözme
    decrypted_data = SecureCrypto.decrypt_data(encrypted_data, key)
    print(f"Decrypted: {decrypted_data}")
    
    # Güvenli token oluşturma
    token = SecureCrypto.generate_secure_token()
    print(f"Secure token: {token}")
    
    # RSA anahtar çifti
    private_key, public_key = SecureCrypto.generate_rsa_keypair()
    print(f"RSA keys generated successfully")
    
    # RSA şifreleme
    rsa_encrypted = SecureCrypto.rsa_encrypt("Secret message", public_key)
    rsa_decrypted = SecureCrypto.rsa_decrypt(rsa_encrypted, private_key)
    print(f"RSA decrypted: {rsa_decrypted}")
    
    # HMAC
    hmac_key = os.urandom(32)
    message = "Important message"
    signature = SecureCrypto.generate_hmac(message, hmac_key)
    is_valid_hmac = SecureCrypto.verify_hmac(message, signature, hmac_key)
    print(f"HMAC valid: {is_valid_hmac}")
    
    # Güvenli depolama
    storage = SecureStorage()
    storage.store_encrypted("Confidential data", "encrypted_file.bin")
    loaded_data = storage.load_encrypted("encrypted_file.bin")
    print(f"Loaded data: {loaded_data}")