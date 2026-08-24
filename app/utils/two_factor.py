"""
Which second factor an account actually requires.

This lives in one place on purpose. The rule is "the strongest configured factor
wins, and it disables the weaker ones" — but that rule was previously expressed as
an inline query in the login handler and enforced nowhere else, so it only ever
*steered* the browser rather than binding the login.

Concretely: a user with both a WebAuthn security key and TOTP was redirected to the
WebAuthn page, yet POSTing straight to /login/totp with a valid TOTP code produced a
full session. The session already carried pending_2fa_user_id, and the TOTP handler
checked only that the user had TOTP enabled. Anyone holding the password and a TOTP
code could therefore step around the security key the account was relying on.

Every path that completes a second factor must consult required_second_factor().
"""

from enum import Enum

from sqlalchemy.orm import Session

from app.models import db as models_db


class SecondFactor(str, Enum):
    NONE = "none"
    TOTP = "totp"
    WEBAUTHN = "webauthn"


def _has_credential(db: Session, user_id: int, usage_mode: str) -> bool:
    return db.query(models_db.WebAuthnCredential.id).filter(
        models_db.WebAuthnCredential.user_id == user_id,
        models_db.WebAuthnCredential.is_active == True,  # noqa: E712
        models_db.WebAuthnCredential.usage_mode == usage_mode,
    ).first() is not None


def has_webauthn_2fa(db: Session, user_id: int) -> bool:
    return _has_credential(db, user_id, '2fa')


def has_passwordless_webauthn(db: Session, user_id: int) -> bool:
    return _has_credential(db, user_id, 'passwordless')


def required_second_factor(db: Session, user: models_db.User) -> SecondFactor:
    """
    The single factor this account must complete after a password.

    WebAuthn outranks TOTP: a hardware authenticator cannot be phished or copied out
    of a screenshot, so when both are registered the weaker one must not be an
    alternative. It is deliberately not "either is fine" — an attacker gets to pick,
    and they will always pick the weaker.
    """
    if has_webauthn_2fa(db, user.id):
        return SecondFactor.WEBAUTHN
    if user.is_totp_enabled:
        return SecondFactor.TOTP
    return SecondFactor.NONE


def totp_is_accepted_for(db: Session, user: models_db.User) -> bool:
    """True only if TOTP is *the* required factor for this account."""
    return required_second_factor(db, user) == SecondFactor.TOTP


def password_login_is_disabled(db: Session, user: models_db.User) -> bool:
    """
    A passwordless-only account must not be reachable by password.

    Registering a passwordless key and no second factor is an explicit statement that
    the password is no longer a way in.
    """
    return (
        has_passwordless_webauthn(db, user.id)
        and required_second_factor(db, user) == SecondFactor.NONE
    )
