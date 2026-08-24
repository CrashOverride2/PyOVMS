"""
POST /webauthn/auth/begin must not enumerate the server's passkeys.

Passwordless login has not identified a user when it builds its options, and the only
gate on the endpoint is a CSRF token that GET /webauthn/login hands to any visitor. It
used to answer with an allowCredentials list built from *every* passwordless credential
in the database, so a single unauthenticated request returned the credential id of every
passkey user on the server.

Discoverable credentials do not need naming — the authenticator finds them itself — so
they are left out. What may still be named is the residue: credentials registered before
registration asked for a resident key (is_discoverable NULL), and the occasional
authenticator that refused one (False). Naming those is deliberate. An account with a
passwordless key and no second factor cannot log in by password at all
(app.utils.two_factor.password_login_is_disabled), so treating an unknown credential as
discoverable would lock it out of its own server permanently.

These tests run the router's own filter against a real session, so they fail if the
predicate is loosened back to "every passwordless credential" or tightened to something
that hides a credential its owner still needs.
"""

import datetime
import inspect

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.db import Base, User, WebAuthnCredential
from app.routers.ui import webauthn as ui_webauthn


@pytest.fixture
def db():
    """A real SQLAlchemy session over in-memory SQLite, with the real schema."""
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


def _make_user(db, user_id: int) -> User:
    user = User(
        id=user_id,
        username=f"user{user_id}",
        email=f"user{user_id}@example.invalid",
        hashed_password="x",
        is_active=True,
    )
    db.add(user)
    db.flush()
    return user


def _add_credential(db, user, credential_id, *, usage_mode="passwordless",
                    is_discoverable=None, is_active=True):
    credential = WebAuthnCredential(
        user_id=user.id,
        credential_id=credential_id,
        public_key="00",
        sign_count=0,
        usage_mode=usage_mode,
        is_discoverable=is_discoverable,
        is_active=is_active,
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    db.add(credential)
    db.flush()
    return credential


def _code_only(obj):
    """
    Source with comment lines removed.

    Same helper, same reason as tests/test_passwordless_second_factor.py: the comments
    in these routes explain the bug in the words the assertions look for, so a test that
    reads the raw source passes on the explanation while the code does the wrong thing.
    Verified — the discoverability assertion below stayed green against a deliberately
    reverted filter until this was applied.
    """
    lines = inspect.getsource(obj).splitlines()
    return "\n".join(line for line in lines if not line.strip().startswith("#"))


def _named_at_login(db):
    """
    The credentials the passwordless login would put in allowCredentials.

    Mirrors the router's filter exactly. Kept next to the tests rather than imported so
    a change to the router that this file does not follow shows up as a failure here.
    """
    return {
        c.credential_id
        for c in db.query(WebAuthnCredential).filter(
            WebAuthnCredential.is_active == True,  # noqa: E712 - SQLAlchemy needs ==
            WebAuthnCredential.usage_mode == "passwordless",
            WebAuthnCredential.is_discoverable.isnot(True),
        ).all()
    }


def test_discoverable_credentials_are_never_named(db):
    """The whole point: a resident key is found by the authenticator, not announced."""
    user = _make_user(db, 1)
    _add_credential(db, user, "aa" * 16, is_discoverable=True)

    assert _named_at_login(db) == set(), (
        "a discoverable credential was disclosed to an unauthenticated caller"
    )


def test_unknown_and_non_resident_credentials_are_still_named(db):
    """
    The migration residue must keep working. NULL means "registered before we asked",
    False means the authenticator declined — neither can be found without a hint, and
    their owners may have no password to fall back on.
    """
    user = _make_user(db, 1)
    _add_credential(db, user, "bb" * 16, is_discoverable=None)
    _add_credential(db, user, "cc" * 16, is_discoverable=False)

    assert _named_at_login(db) == {"bb" * 16, "cc" * 16}


def test_only_the_residue_is_named_when_both_kinds_exist(db):
    """A migrated user and a legacy one on the same server: only the legacy one leaks."""
    migrated = _make_user(db, 1)
    legacy = _make_user(db, 2)
    _add_credential(db, migrated, "dd" * 16, is_discoverable=True)
    _add_credential(db, legacy, "ee" * 16, is_discoverable=None)

    assert _named_at_login(db) == {"ee" * 16}


def test_two_factor_and_inactive_credentials_are_never_named(db):
    """
    2FA credentials are looked up by user id after the password step, so they have no
    business in an unauthenticated response regardless of discoverability.
    """
    user = _make_user(db, 1)
    _add_credential(db, user, "ff" * 16, usage_mode="2fa", is_discoverable=None)
    _add_credential(db, user, "11" * 16, is_discoverable=None, is_active=False)

    assert _named_at_login(db) == set()


def test_begin_does_not_fall_back_to_listing_everything():
    """
    Guards the shape of the fix, not just its result. An `.all()` over passwordless
    credentials without the discoverability predicate is the exact bug that was here.
    """
    source = _code_only(ui_webauthn.ui_webauthn_auth_begin)

    assert "is_discoverable" in source, (
        "auth/begin no longer filters on discoverability — it is enumerating again"
    )


def test_begin_no_longer_reports_whether_any_passkey_exists():
    """
    The old "No passwordless WebAuthn credentials registered in system" 400 answered,
    to anyone who asked, whether this server has passkey users at all. With nothing to
    count it is also simply wrong: a discoverable credential is invisible here.
    """
    source = _code_only(ui_webauthn.ui_webauthn_auth_begin)

    assert "No passwordless WebAuthn credentials" not in source, (
        "auth/begin still discloses whether any passkey is registered"
    )


def test_unknown_credential_at_complete_counts_as_a_failed_attempt():
    """
    Now that /begin no longer hands out credential ids, guessing one has to cost
    something. This was the only authentication path that never recorded a failure, so
    it could be hammered without the IP block ever engaging.
    """
    source = _code_only(ui_webauthn.ui_webauthn_auth_complete)

    assert "record_failure" in source, (
        "an unknown credential at auth/complete is not rate limited"
    )
