from cryptography.fernet import Fernet
from typing import Optional
import base64

from app.config import settings

_fernet_instance: Optional[Fernet] = None

def get_fernet() -> Fernet:
    """Initializes and returns a singleton Fernet instance for encryption."""
    global _fernet_instance
    if _fernet_instance is None:
        key_str = settings.TOTP_ENCRYPTION_KEY
        try:
            key_bytes = key_str.encode('utf-8')
            decoded_key_for_validation = base64.urlsafe_b64decode(key_bytes)
            if len(decoded_key_for_validation) != 32:
                raise ValueError("TOTP_ENCRYPTION_KEY must be a URL-safe base64-encoded string that decodes to 32 bytes.")
            _fernet_instance = Fernet(key_bytes)
        except base64.binascii.Error:
             raise ValueError("TOTP_ENCRYPTION_KEY is not a valid URL-safe base64-encoded string.")
        except Exception as e: 
             raise ValueError(f"Error initializing Fernet with TOTP_ENCRYPTION_KEY: {e}")
    return _fernet_instance

def encrypt_data(data: str) -> bytes:
    """Encrypts a string using the global Fernet instance."""
    fernet = get_fernet()
    return fernet.encrypt(data.encode('utf-8'))

def decrypt_data(encrypted_data: bytes) -> str:
    """Decrypts data using the global Fernet instance."""
    fernet = get_fernet()
    return fernet.decrypt(encrypted_data).decode('utf-8')