import base64
import hmac
import hashlib
import secrets
from Crypto.Cipher import ARC4

B64_TAB = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


class DecryptionError(ValueError):
    """An incoming V2 line could not be base64-decoded or decrypted to text.

    Subclasses ValueError so callers that already catch ValueError keep working.
    """

def generate_server_token() -> str: 
    """Generates a 22-character random string using the V2 protocol's base64 alphabet."""
    return "".join(secrets.choice(B64_TAB) for _ in range(22))

def calculate_hmac_b64digest(key: str, data: str) -> str:
    """Calculates an MD5 HMAC and returns it as a standard base64 encoded string."""
    h = hmac.new(key.encode('utf-8'), data.encode('utf-8'), hashlib.md5)
    return base64.b64encode(h.digest()).decode('utf-8').strip() 

def calculate_hmac_digest(key: str, data: str) -> bytes:
    """Calculates an MD5 HMAC and returns the raw digest bytes."""
    h = hmac.new(key.encode('utf-8'), data.encode('utf-8'), hashlib.md5)
    return h.digest()

def create_rc4_cipher(key: bytes) -> ARC4.ARC4Cipher:
    """Creates an RC4 cipher instance and discards the initial pseudo-random output as required by the V2 protocol."""
    cipher = ARC4.new(key)
    cipher.encrypt(b'\0' * 1024)
    return cipher

def rc4_encrypt_b64(cipher: ARC4.ARC4Cipher, data: str) -> str:
    """Encrypts a string with the given RC4 cipher and base64 encodes the result."""
    encrypted_bytes = cipher.encrypt(data.encode('utf-8'))
    return base64.b64encode(encrypted_bytes).decode('utf-8').strip()

def rc4_decrypt_b64(cipher: ARC4.ARC4Cipher, b64_data: str) -> str:
    """Base64 decodes data and decrypts it with the given RC4 cipher."""
    try:
        encrypted_bytes = base64.b64decode(b64_data.encode('utf-8'))
        return cipher.decrypt(encrypted_bytes).decode('utf-8')
    except (UnicodeDecodeError, base64.binascii.Error) as e:
        raise DecryptionError(f"RC4 Decryption/Decode Error: {e}") from e