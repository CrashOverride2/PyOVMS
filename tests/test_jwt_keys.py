"""
Tests for the move from a shared HS256 secret to Ed25519 session tokens.

The old scheme signed session JWTs with SECRET_KEY_JWT and required that same secret to
be copied into the Karto service so it could validate cookies. With a symmetric
algorithm, verifying and minting are one capability: anyone able to read Karto's
configuration could issue a token for any user of the main server, administrators
included. Karto only ever needed to verify.

These tests pin the properties that make the split meaningful — the algorithm is not
negotiable, the audience is checked, and a token signed with anything else is refused.
"""

import base64
import datetime

import jwt as pyjwt
import pytest

from app import jwt_keys, security
from app.config import settings


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


# --- key handling -------------------------------------------------------------------

def test_generated_keypair_matches():
    priv_b64, pub_b64 = jwt_keys.generate_keypair()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64))
    derived = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    assert base64.b64encode(derived).decode() == pub_b64


def test_configured_public_key_matches_the_private_key():
    """A mismatched pair would mint tokens the server itself cannot verify."""
    assert jwt_keys.public_key_b64() == settings.JWT_PUBLIC_KEY


@pytest.mark.parametrize("bad", ["not-base64!!", base64.b64encode(b"tooshort").decode(), ""])
def test_malformed_key_material_is_rejected(monkeypatch, bad):
    monkeypatch.setattr(settings, "JWT_PRIVATE_KEY", bad)
    jwt_keys._reset_cache()
    try:
        with pytest.raises(jwt_keys.JwtKeyError):
            jwt_keys.get_private_key()
    finally:
        jwt_keys._reset_cache()


# --- the tokens the server issues ----------------------------------------------------

def test_issued_token_uses_eddsa_and_carries_audience_and_issuer():
    token = security.create_access_token_with_2fa_status("alice", True, token_version=0)

    assert pyjwt.get_unverified_header(token)["alg"] == "EdDSA"

    payload = pyjwt.decode(
        token, jwt_keys.get_public_key(), algorithms=["EdDSA"],
        audience=jwt_keys.JWT_AUDIENCE, issuer=jwt_keys.JWT_ISSUER,
    )
    assert payload["sub"] == "alice"
    assert payload["aud"] == jwt_keys.JWT_AUDIENCE
    assert payload["iss"] == jwt_keys.JWT_ISSUER


def test_the_public_key_alone_cannot_sign():
    """The property the whole migration rests on: Karto holds only this key."""
    with pytest.raises(Exception):
        pyjwt.encode({"sub": "admin"}, jwt_keys.get_public_key(), algorithm="EdDSA")


# --- what must be refused -------------------------------------------------------------

def test_token_signed_with_the_old_shared_secret_is_refused():
    """
    The exact attack the change removes: HS256 with the symmetric secret that used to
    live on the Karto host.
    """
    forged = pyjwt.encode(
        {"sub": "admin", "mfa": True, "ver": 0, "exp": _now() + datetime.timedelta(hours=1),
         "aud": jwt_keys.JWT_AUDIENCE, "iss": jwt_keys.JWT_ISSUER},
        settings.SECRET_KEY_JWT, algorithm="HS256",
    )
    with pytest.raises(pyjwt.InvalidTokenError):
        pyjwt.decode(
            forged, jwt_keys.get_public_key(), algorithms=["EdDSA"],
            audience=jwt_keys.JWT_AUDIENCE, issuer=jwt_keys.JWT_ISSUER,
        )


def test_token_from_a_different_keypair_is_refused():
    other_priv, _ = jwt_keys.generate_keypair()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    forged = pyjwt.encode(
        {"sub": "admin", "exp": _now() + datetime.timedelta(hours=1),
         "aud": jwt_keys.JWT_AUDIENCE, "iss": jwt_keys.JWT_ISSUER},
        Ed25519PrivateKey.from_private_bytes(base64.b64decode(other_priv)), algorithm="EdDSA",
    )
    with pytest.raises(pyjwt.InvalidTokenError):
        pyjwt.decode(
            forged, jwt_keys.get_public_key(), algorithms=["EdDSA"],
            audience=jwt_keys.JWT_AUDIENCE, issuer=jwt_keys.JWT_ISSUER,
        )


def test_token_with_a_foreign_audience_is_refused():
    """Guards against a future token type signed with the same key being replayed."""
    other_audience = pyjwt.encode(
        {"sub": "alice", "exp": _now() + datetime.timedelta(hours=1),
         "aud": "password-reset", "iss": jwt_keys.JWT_ISSUER},
        jwt_keys.get_private_key(), algorithm="EdDSA",
    )
    with pytest.raises(pyjwt.InvalidAudienceError):
        pyjwt.decode(
            other_audience, jwt_keys.get_public_key(), algorithms=["EdDSA"],
            audience=jwt_keys.JWT_AUDIENCE, issuer=jwt_keys.JWT_ISSUER,
        )


def test_algorithm_is_fixed_not_configurable():
    """
    A settings-driven algorithm could be widened by a config mistake; the decode side
    must always pass a one-element allowlist.
    """
    import inspect

    source = inspect.getsource(security.decode_jwt_and_get_user)
    assert "algorithms=[jwt_keys.JWT_ALGORITHM]" in source
    assert not hasattr(settings, "ALGORITHM"), "ALGORITHM must no longer be a setting"
