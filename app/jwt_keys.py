"""
Ed25519 key material for session tokens.

Previously the session JWT was signed with HS256 using SECRET_KEY_JWT, and that same
secret had to be copied into the Karto service so it could validate cookies. Symmetric
signing means *verifying* and *minting* are the same capability: anyone who could read
Karto's configuration could issue a token for any user of the main server, administrators
included. Karto only ever needed to verify.

With Ed25519 the main server holds the private key and Karto holds only the public one,
so a compromise there can no longer produce a valid session anywhere.

Keys are carried as base64 of the raw 32-byte values rather than PEM, so they stay
single-line and fit the existing .env format:

    JWT_PRIVATE_KEY   base64(32-byte Ed25519 seed)     main server only
    JWT_PUBLIC_KEY    base64(32-byte Ed25519 public)   main server and Karto

SECRET_KEY_JWT stays in use, but only for CSRF token signing — that is a purely local
concern and is never shared with another service.
"""

import base64
import functools

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.config import settings

# The signature algorithm is fixed, not configurable. It is passed to PyJWT as a
# single-element allowlist on every decode; making it a setting would let a
# misconfiguration widen what the server accepts.
JWT_ALGORITHM = "EdDSA"

# Session tokens carry this audience so a future token type signed with the same key
# (a reset link, a device token) is not silently accepted as a session by either service.
JWT_AUDIENCE = "ovms-session"
JWT_ISSUER = "ovms-server"


class JwtKeyError(RuntimeError):
    """Raised when the configured key material is missing or malformed."""


def _decode_b64(value: str, field: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise JwtKeyError(f"{field} is not valid base64: {exc}") from exc
    if len(raw) != 32:
        raise JwtKeyError(f"{field} must decode to exactly 32 bytes, got {len(raw)}.")
    return raw


@functools.lru_cache(maxsize=1)
def get_private_key() -> Ed25519PrivateKey:
    if not settings.JWT_PRIVATE_KEY:
        raise JwtKeyError(
            "JWT_PRIVATE_KEY is not set. Run run.py once to generate a key pair, or "
            "generate one with: python -m app.jwt_keys"
        )
    return Ed25519PrivateKey.from_private_bytes(_decode_b64(settings.JWT_PRIVATE_KEY, "JWT_PRIVATE_KEY"))


@functools.lru_cache(maxsize=1)
def get_public_key() -> Ed25519PublicKey:
    """
    Public key used to verify session tokens.

    Derived from the private key when only that is configured, so the main server cannot
    end up verifying against a public key that does not match what it signs with.
    """
    if settings.JWT_PUBLIC_KEY:
        return Ed25519PublicKey.from_public_bytes(_decode_b64(settings.JWT_PUBLIC_KEY, "JWT_PUBLIC_KEY"))
    return get_private_key().public_key()


def _encode_public(key: Ed25519PublicKey) -> str:
    from cryptography.hazmat.primitives import serialization

    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode()


def public_key_b64() -> str:
    """
    The verification key this server actually uses, as configured.

    Note this returns JWT_PUBLIC_KEY verbatim when that is set — it is what tokens
    are checked against, not necessarily what the private key produces. Use
    derived_public_key_b64() when you need to know what the private key implies.
    """
    return _encode_public(get_public_key())


def derived_public_key_b64() -> str:
    """
    The public key belonging to the configured JWT_PRIVATE_KEY.

    Deliberately bypasses get_public_key(), which prefers a configured
    JWT_PUBLIC_KEY. Comparing the two is the only way to detect a mismatched pair;
    comparing public_key_b64() against the setting compares the setting with itself
    and can never fail, which is how a startup guard for exactly this ended up
    passing a deliberately mismatched pair.
    """
    return _encode_public(get_private_key().public_key())


def generate_keypair() -> tuple[str, str]:
    """Return a fresh (private_b64, public_b64) pair."""
    from cryptography.hazmat.primitives import serialization

    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(private_raw).decode(), base64.b64encode(public_raw).decode()


def _reset_cache() -> None:
    """Drop memoised keys (tests change the settings object at runtime)."""
    get_private_key.cache_clear()
    get_public_key.cache_clear()


if __name__ == "__main__":
    priv, pub = generate_keypair()
    print("# OVMS main server (.env) — keep the private key secret:")
    print(f"JWT_PRIVATE_KEY={priv}")
    print(f"JWT_PUBLIC_KEY={pub}")
    print()
    print("# Karto service (karto.env) — public key only:")
    print(f"JWT_PUBLIC_KEY={pub}")
