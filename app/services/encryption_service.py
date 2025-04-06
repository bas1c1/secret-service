from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
from app.config import settings


class EncryptionService:
    """Service for encrypting and decrypting secrets."""
    
    @staticmethod
    def generate_key(passphrase: str = None) -> bytes:
        """Generate encryption key from passphrase or settings."""
        if passphrase:
            # Derive key from passphrase
            salt = base64.b64decode(settings.SECRET_KEY)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = kdf.derive(passphrase.encode())
            return key
        else:
            # Use application secret key
            return base64.b64decode(settings.SECRET_KEY)[:32]
    
    @staticmethod
    def encrypt(data: str, passphrase: str = None) -> tuple:
        """Encrypt data using AES-GCM."""
        key = EncryptionService.generate_key(passphrase)
        aesgcm = AESGCM(key)
        
        # Generate a random 96-bit IV
        iv = os.urandom(12)
        
        # Encrypt the data
        encrypted_data = aesgcm.encrypt(iv, data.encode(), None)
        
        return base64.b64encode(encrypted_data).decode(), base64.b64encode(iv).decode()
    
    @staticmethod
    def decrypt(encrypted_data: str, iv: str, passphrase: str = None) -> str:
        """Decrypt data using AES-GCM."""
        key = EncryptionService.generate_key(passphrase)
        aesgcm = AESGCM(key)
        
        # Decode base64 strings
        encrypted_bytes = base64.b64decode(encrypted_data)
        iv_bytes = base64.b64decode(iv)
        
        # Decrypt the data
        decrypted_data = aesgcm.decrypt(iv_bytes, encrypted_bytes, None)
        
        return decrypted_data.decode()
    
    @staticmethod
    def hash_passphrase(passphrase: str) -> str:
        """Create a hash of the passphrase for storage."""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(passphrase.encode())
        return base64.b64encode(digest.finalize()).decode()

