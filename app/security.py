import base64
import hashlib
import logging
import secrets
import threading
import time
from typing import Optional
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt as pyjwt
from jwt.exceptions import InvalidTokenError
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app import jwt_keys
from app.models import db as models_db
import pyotp
import qrcode
import qrcode.image.svg
from io import BytesIO

logger = logging.getLogger(__name__)

# Fallback cache for consumed TOTP codes, used only while the database is unreachable.
# The real record lives in the used_totp_codes table — see _claim_totp_code() — because
# a dictionary here is per worker process, and a replay only has to reach a different
# process to succeed. Key: hash of secret and code, value: unix timestamp of first use.
_used_totp_codes: dict[str, float] = {}
_used_totp_lock = threading.Lock()

# bcrypt is used directly instead of through passlib: passlib is unmaintained
# since 2020 and its bcrypt backend fails outright against bcrypt >= 5, which no
# longer truncates silently. The hash format ($2b$, 12 rounds) is unchanged, so
# existing hashes keep verifying.
BCRYPT_ROUNDS = 12
# bcrypt only ever considered the first 72 bytes; passlib truncated for us. Keep
# doing it explicitly, otherwise bcrypt >= 5 rejects longer passwords and users
# with one would be locked out of their existing account.
BCRYPT_MAX_BYTES = 72


def _bcrypt_secret(password: str) -> bytes:
    return password.encode('utf-8')[:BCRYPT_MAX_BYTES]

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(_bcrypt_secret(plain_password), hashed_password.encode('utf-8'))
    except (ValueError, TypeError):
        # Malformed or unsupported hash in the database: treat as a failed login.
        return False

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(_bcrypt_secret(password), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode('utf-8')


_dummy_password_hash: Optional[bytes] = None


def _get_dummy_password_hash() -> bytes:
    global _dummy_password_hash
    if _dummy_password_hash is None:
        # Two threads racing here both produce a usable hash; the loser is discarded.
        _dummy_password_hash = bcrypt.hashpw(
            secrets.token_bytes(32), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
        )
    return _dummy_password_hash


def verify_password_for_user(user: Optional[models_db.User], password: str) -> bool:
    """
    Verify `password` against `user`, spending bcrypt time even when `user` is None.

    The call sites used to read `if not user or not verify_password(...)`, which skips
    bcrypt entirely for an unknown username. bcrypt at 12 rounds takes ~250 ms, so the
    response time answered the question the deliberately generic error message
    refuses to answer: whether the account exists. Every path that checks a password
    against a user that may not exist goes through here, so the property cannot be
    lost by adding a fourth such path later.
    """
    if user is None or not user.hashed_password:
        bcrypt.checkpw(_bcrypt_secret(password), _get_dummy_password_hash())
        return False
    return verify_password(password, user.hashed_password)


def generate_email_verification_token() -> str:
    """Generates a secure, URL-safe token."""
    return secrets.token_urlsafe(32)


def hash_url_token(token: str) -> str:
    """
    Hash a token that travels in a URL (email verification, password reset).

    Stored hashed for the same reason API keys are: the raw value in a database dump
    is a working credential. SHA-256 without a salt or a work factor is the right
    choice here and not a shortcut — the input is 32 bytes from `secrets`, so there
    is no guessable preimage to slow an attacker down to, and the lookup has to find
    the row by value.
    """
    return hashlib.sha256(token.encode('utf-8')).hexdigest()

def create_access_token_with_2fa_status(
    username: str,
    is_2fa_completed: bool,
    expires_delta: Optional[timedelta] = None,
    token_version: int = 0,
) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload = {
        "sub": username,
        "mfa": is_2fa_completed,
        "exp": expire,
        "ver": token_version,
        # Pin what this token is for. Karto verifies the same audience, so a future
        # token type signed with the same key cannot be replayed as a session.
        "aud": jwt_keys.JWT_AUDIENCE,
        "iss": jwt_keys.JWT_ISSUER,
    }
    return pyjwt.encode(payload, jwt_keys.get_private_key(), algorithm=jwt_keys.JWT_ALGORITHM)

async def decode_jwt_and_get_user(
    token: Optional[str], db: Session, ignore_mfa_check: bool = False
) -> Optional[models_db.User]:
    if not token:
        return None

    from app import crud

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials (JWT)",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        token_value = token.split(' ', 1)[1] if token.startswith("Bearer ") else token
        payload = pyjwt.decode(
            token_value,
            jwt_keys.get_public_key(),
            algorithms=[jwt_keys.JWT_ALGORITHM],  # explicit allowlist prevents alg:none attack
            audience=jwt_keys.JWT_AUDIENCE,
            issuer=jwt_keys.JWT_ISSUER,
        )
    except InvalidTokenError:
        raise credentials_exception

    username: Optional[str] = payload.get("sub")
    is_2fa_completed: bool = payload.get("mfa", False)
    token_ver: int = payload.get("ver", 0)

    if not username:
        raise credentials_exception

    user = crud.user.get_user_by_username(db, username=username)
    if user is None:
        raise credentials_exception

    if token_ver != (user.token_version or 0):
        raise credentials_exception

    if not ignore_mfa_check and user.is_totp_enabled and not is_2fa_completed:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="2FA required but not completed in this token session.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user

def generate_totp_secret() -> str:
    return pyotp.random_base32()

def get_totp_uri(secret: str, username: str, issuer_name: str = settings.OTP_ISSUER_NAME) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer_name)

# How long a code stays replayable: the 30 s step plus one step either side, which is
# what valid_window=1 accepts.
TOTP_REPLAY_WINDOW_SECONDS = 90


def _totp_code_key(secret: str, code: str) -> str:
    """
    Identify a (secret, code) pair without storing either.

    The secret is included so two users whose codes happen to coincide do not lock
    each other out; it is hashed together with the code so the stored value reveals
    neither.
    """
    return hashlib.sha256(f"{secret}:{code}".encode('utf-8')).hexdigest()


def _claim_totp_code_in_memory(cache_key: str) -> bool:
    """Process-local fallback claim. True if the code was unused."""
    now = time.time()
    with _used_totp_lock:
        stale = [k for k, t in _used_totp_codes.items() if now - t > TOTP_REPLAY_WINDOW_SECONDS]
        for k in stale:
            del _used_totp_codes[k]
        if cache_key in _used_totp_codes:
            return False  # replay detected
        _used_totp_codes[cache_key] = now
    return True


def _claim_totp_code(secret: str, code: str) -> bool:
    """
    Mark a TOTP code as spent, returning False if it had already been used.

    Backed by the database so the guarantee survives more than one worker process:
    the in-process dictionary this replaced meant a captured code could simply be
    replayed against a different worker. The unique index on `code_key` makes the
    claim atomic — the insert *is* the check, so two simultaneous requests carrying
    the same code cannot both be told they were first.

    On any database error it falls back to the in-process dictionary rather than
    rejecting the login: an unreachable database would otherwise lock out every 2FA
    user, and the fallback is exactly the protection that existed before.
    """
    cache_key = _totp_code_key(secret, code)

    try:
        from app.database import SessionLocal
        from app.models.db import UsedTotpCode
        from sqlalchemy.exc import IntegrityError

        db = SessionLocal()
        try:
            now = datetime.now(timezone.utc)

            # Housekeeping first: rows outside the window can never indicate a replay,
            # and leaving them would grow the table without bound.
            db.query(UsedTotpCode).filter(
                UsedTotpCode.used_at < now - timedelta(seconds=TOTP_REPLAY_WINDOW_SECONDS)
            ).delete(synchronize_session=False)

            db.add(UsedTotpCode(code_key=cache_key, used_at=now))
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                return False  # replay detected: the key was already claimed
            return True
        finally:
            db.close()
    except Exception as e:
        logger.warning(
            f"TOTP replay check fell back to the in-process cache: {e}. "
            "Replay protection is per-worker until the database is reachable again."
        )
        return _claim_totp_code_in_memory(cache_key)


def verify_totp_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    # valid_window=1 accepts the previous 30-second step to tolerate minor clock drift.
    if not totp.verify(code, valid_window=1):
        return False
    return _claim_totp_code(secret, code)

def generate_qr_code_data_uri(otpauth_uri: str) -> str:
    img_png = qrcode.make(otpauth_uri)
    buffered_png = BytesIO()
    img_png.save(buffered_png, format="PNG")
    img_str_b64 = base64.b64encode(buffered_png.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{img_str_b64}"
