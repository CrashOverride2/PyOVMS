from sqlalchemy.orm import Session
from sqlalchemy import func
import datetime
import logging
from typing import Optional, List

from app.models import db as models_db
from app.models import api as models_api
from app import security
from app.config import settings
from app.services.mqtt_sync_worker import mqtt_sync_worker

logger = logging.getLogger(__name__)

def get_user_by_id(db: Session, user_id: int) -> Optional[models_db.User]:
    return db.query(models_db.User).filter(models_db.User.id == user_id).first()

def get_user_by_username(db: Session, username: str) -> Optional[models_db.User]:
    return db.query(models_db.User).filter(models_db.User.username == username).first()

def get_user_by_email(db: Session, email: str) -> Optional[models_db.User]:
    return db.query(models_db.User).filter(models_db.User.email == email).first()

def get_users(db: Session, skip: int = 0, limit: int = 100) -> List[models_db.User]:
    return db.query(models_db.User).order_by(models_db.User.username).offset(skip).limit(limit).all()

def get_non_admin_users(db: Session, skip: int = 0, limit: int = 10000) -> List[models_db.User]:
    """Retrieves all non-administrator users from the database."""
    return db.query(models_db.User).filter(models_db.User.is_admin == False).order_by(models_db.User.username).offset(skip).limit(limit).all()

def get_user_count(db: Session) -> int:
    return db.query(func.count(models_db.User.id)).scalar()

def get_active_admins(db: Session) -> List[models_db.User]:
    """Retrieves all active administrator users from the database."""
    return db.query(models_db.User).filter(models_db.User.is_admin == True, models_db.User.is_active == True).all()


def is_last_active_admin(db: Session, user: models_db.User) -> bool:
    """
    Whether `user` is an active admin and no other active admin exists.

    The invariant is "this server always has at least one account that can administer
    it". Self-service account deletion has checked it since it was written
    (ui/profile.py), because that is the one path where an admin can plainly remove
    themselves. The admin-facing routes did not, on the reasoning that the actor is
    themselves an active admin and cannot demote, deactivate or delete their own
    account — so one always remains.

    That reasoning is correct today and is exactly the kind that stops being correct
    quietly: it depends on three separate self-checks in two routers staying in place.
    Asserting the invariant where it is actually about to be broken costs one query
    and does not depend on any of them.
    """
    if not (user.is_admin and user.is_active):
        return False
    return (
        db.query(func.count(models_db.User.id))
        .filter(
            models_db.User.is_admin == True,
            models_db.User.is_active == True,
            models_db.User.id != user.id,
        )
        .scalar()
    ) == 0

def create_user(db: Session, user_in: models_api.UserCreate) -> models_db.User:
    hashed_password = security.get_password_hash(user_in.password)
    db_user = models_db.User(
        username=user_in.username,
        email=user_in.email,
        full_name=user_in.full_name,
        hashed_password=hashed_password,
        is_active=user_in.is_active,
        is_admin=user_in.is_admin,
        timezone=user_in.timezone,
        created_at=datetime.datetime.now(datetime.timezone.utc),
        updated_at=datetime.datetime.now(datetime.timezone.utc)
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def increment_token_version(db: Session, user: models_db.User) -> None:
    """Invalidate all existing JWTs for this user by bumping the version counter."""
    user.token_version = (user.token_version or 0) + 1
    user.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()

def update_user(db: Session, user_db: models_db.User, user_in: models_api.UserUpdate) -> models_db.User:
    update_data = user_in.model_dump(exclude_unset=True)
    old_username = user_db.username
    old_is_active = user_db.is_active
    password_changed = bool(update_data.get("password"))

    if password_changed:
        hashed_password = security.get_password_hash(update_data["password"])
        user_db.hashed_password = hashed_password
        user_db.token_version = (user_db.token_version or 0) + 1

    for field, value in update_data.items():
        if field != "password":
            setattr(user_db, field, value)

    user_db.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(user_db)

    # A changed password revokes the provisioned device keys, exactly as a reset does.
    #
    # reset_user_password() has done this since round 7, but every *other* way to set a
    # password runs through here: the profile page, PUT /users/me/password, and an admin
    # editing the account. Those are the first thing a person reaches for after a
    # suspected compromise — a reset link is the fallback, not the default — so leaving
    # the device keys alone here reopened N-8 on the busier path. Bumping token_version
    # above ends the browser sessions; without this the phone's key survived, and since
    # it slides its own expiry forward on every use it never lapsed on its own either.
    if password_changed:
        from app.crud import apikey as crud_apikey

        revoked = crud_apikey.revoke_device_keys_for_user(db, user_id=user_db.id)
        if revoked:
            logger.info(
                f"Password change for '{user_db.username}': revoked {revoked} device "
                f"key(s). Paired devices must sign in again."
            )

    if 'username' in update_data and user_db.username != old_username:
        logger.info(f"MQTT: Username changed from '{old_username}' to '{user_db.username}'. Queueing ACL regeneration.")
        mqtt_sync_worker.mark_acl_dirty()

    # Activation state decides what the broker grants, so it has to reach the broker.
    # Nothing used to queue a resync here: the ACL and password files kept the old
    # state until the next restart, which meant "deactivate this account" left MQTT
    # fully open for as long as the process happened to stay up.
    if 'is_active' in update_data and user_db.is_active != old_is_active:
        state = "activated" if user_db.is_active else "deactivated"
        logger.info(
            f"MQTT: User '{user_db.username}' {state}. Queueing credential resync for "
            f"their vehicles and ACL regeneration."
        )
        _queue_broker_resync_for_user(db, user_db)

    return user_db


def _queue_broker_resync_for_user(db: Session, user_db: models_db.User) -> None:
    """Re-derive broker credentials for every vehicle this user owns, plus the ACL."""
    owned_vehicle_ids = [
        v.vehicle_id
        for v in db.query(models_db.Vehicle).filter(models_db.Vehicle.owner_id == user_db.id).all()
    ]
    for vehicle_id in owned_vehicle_ids:
        mqtt_sync_worker.mark_vehicle_dirty(vehicle_id)
    mqtt_sync_worker.mark_acl_dirty()

def delete_user(db: Session, user_id: int) -> Optional[models_db.User]:
    db_user = get_user_by_id(db, user_id)
    if db_user:
        logger.warning(f"DELETING user '{db_user.username}' (ID: {db_user.id}). All associated data (vehicles, logs, API keys) will be deleted by cascade.")

        # Note the owned vehicles before the cascade removes them: their broker
        # logins have to be revoked explicitly, an ACL rebuild alone would leave
        # the password entries behind.
        owned_vehicle_ids = [
            v.vehicle_id for v in db.query(models_db.Vehicle).filter(models_db.Vehicle.owner_id == db_user.id).all()
        ]

        db.delete(db_user)
        db.commit()

        for vehicle_id in owned_vehicle_ids:
            mqtt_sync_worker.mark_vehicle_dirty(vehicle_id)
        mqtt_sync_worker.mark_acl_dirty()
    return db_user

# --- Email Verification ---
#
# Both token columns below hold a SHA-256 hash, never the value that was mailed out.
# The raw token is returned to the caller once, to build the link, and is
# unrecoverable afterwards — a database dump no longer contains a working
# account-takeover credential. Lookups hash the incoming token and compare hashes,
# which is the same shape as crud.apikey and keeps the unique index usable.
def get_user_by_verification_token(db: Session, token: str) -> Optional[models_db.User]:
    if not token:
        return None
    return db.query(models_db.User).filter(
        models_db.User.email_verification_token == security.hash_url_token(token)
    ).first()

def set_user_verification_token(db: Session, user: models_db.User) -> str:
    token = security.generate_email_verification_token()
    token_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS)
    user.email_verification_token = security.hash_url_token(token)
    user.email_verification_token_expires_at = token_expiry
    user.is_active = False 
    db.commit()
    db.refresh(user)
    return token

def activate_user_and_clear_token(db: Session, user: models_db.User) -> models_db.User:
    user.is_active = True
    user.email_verification_token = None
    user.email_verification_token_expires_at = None
    user.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(user)
    return user

# --- TOTP (2FA) ---
def enable_totp_for_user(db: Session, user: models_db.User, totp_secret: str) -> models_db.User:
    from app.utils.crypto import encrypt_data
    user.encrypted_totp_secret = encrypt_data(totp_secret)
    # Record which key the secret was encrypted with. encrypt_data() always uses
    # TOTP_ENCRYPTION_KEY, which the key manager knows as version 1. Writing it
    # explicitly means a row can never be ambiguous about its own key version —
    # NULL used to mean "probably v1", and that guess is what the rotation relied on.
    user.totp_key_version = 1
    user.is_totp_enabled = True
    # Changing the second factor invalidates every existing session. Turning 2FA on
    # or off is the action a user takes after suspecting someone else has access, and
    # without this it left every already-issued token working — there was no way to
    # log other sessions out at all.
    user.token_version = (user.token_version or 0) + 1
    user.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(user)
    return user

def disable_totp_for_user(db: Session, user: models_db.User) -> models_db.User:
    user.encrypted_totp_secret = None
    user.totp_key_version = None
    user.is_totp_enabled = False
    # See enable_totp_for_user(): a change to the second factor ends other sessions.
    user.token_version = (user.token_version or 0) + 1
    user.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(user)
    return user

def get_decrypted_totp_secret_for_user(user: models_db.User) -> Optional[str]:
    """
    Decrypt a user's TOTP secret using the key version their row was encrypted with.

    This must stay key-version aware. It previously called decrypt_data() directly,
    which only ever uses TOTP_ENCRYPTION_KEY (version 1) — while the admin
    "rotate TOTP keys" action re-encrypts every secret with TOTP_ENCRYPTION_KEY_V2
    and records totp_key_version=2. The result was that pressing that button locked
    every 2FA user out of the server permanently, recoverable only via direct DB
    access. This is the single decryption path used by the login flow, so the
    version lookup belongs here rather than at the call site.
    """
    if not user.encrypted_totp_secret:
        return None

    from app.totp_key_rotation import totp_key_manager

    key_version = getattr(user, "totp_key_version", None) or 1
    try:
        return totp_key_manager.decrypt_totp_secret(user.encrypted_totp_secret, key_version)
    except Exception as e:
        logger.error(
            f"Failed to decrypt TOTP secret for user {user.username} "
            f"with key version {key_version}: {e}",
            exc_info=True,
        )
        return None

# --- Password Reset ---
def get_user_by_password_reset_token(db: Session, token: str) -> Optional[models_db.User]:
    """Get a user by their password reset token. See the note above on hashing."""
    if not token:
        return None
    return db.query(models_db.User).filter(
        models_db.User.password_reset_token == security.hash_url_token(token)
    ).first()

def set_password_reset_token(db: Session, user: models_db.User) -> str:
    """
    Generate a password reset token, store its hash and return the raw token.

    The raw value exists only long enough to go into the mail; it is never written
    to the database.
    """
    token = security.generate_email_verification_token()  # Reuse the same secure token generator
    token_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=settings.PASSWORD_RESET_TOKEN_EXPIRE_HOURS)
    user.password_reset_token = security.hash_url_token(token)
    user.password_reset_token_expires_at = token_expiry
    db.commit()
    db.refresh(user)
    return token

def clear_password_reset_token(db: Session, user: models_db.User) -> models_db.User:
    """Clear the password reset token after successful password reset."""
    user.password_reset_token = None
    user.password_reset_token_expires_at = None
    user.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(user)
    return user

def reset_user_password(db: Session, user: models_db.User, new_password: str) -> models_db.User:
    """
    Reset a user's password, clear the reset token, and revoke every existing
    credential: JWT sessions via token_version, and the provisioned device keys.

    A reset is what someone does *after* losing control of their account, so it has
    to close every door and not just the browser one. See
    crud.apikey.revoke_device_keys_for_user() for why device keys in particular.
    """
    user.hashed_password = security.get_password_hash(new_password)
    user.password_reset_token = None
    user.password_reset_token_expires_at = None
    user.token_version = (user.token_version or 0) + 1
    user.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(user)

    from app.crud import apikey as crud_apikey

    revoked = crud_apikey.revoke_device_keys_for_user(db, user_id=user.id)
    if revoked:
        logger.info(
            f"Password reset for '{user.username}': revoked {revoked} device key(s). "
            f"Paired devices must sign in again."
        )

    return user


# --- Lifecycle Management ---

def record_login(db: Session, user: models_db.User) -> None:
    """Record a successful login and cancel any pending account deletion."""
    user.last_login_at = datetime.datetime.now(datetime.timezone.utc)
    user.account_deletion_reminder_sent_at = None
    db.commit()


def get_users_needing_deletion_warning(db: Session, no_login_days: int = 30) -> List[models_db.User]:
    """
    Non-admin active users with no vehicles and no login for no_login_days,
    where no deletion warning has been sent yet.
    """
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=no_login_days)
    candidates = (
        db.query(models_db.User)
        .filter(
            models_db.User.is_admin == False,
            models_db.User.is_active == True,
            models_db.User.account_deletion_reminder_sent_at.is_(None),
            ~models_db.User.vehicles.any(),
        )
        .all()
    )
    result = []
    for user in candidates:
        ref = user.last_login_at or user.created_at
        if ref:
            ref_aware = ref if ref.tzinfo else ref.replace(tzinfo=datetime.timezone.utc)
            if ref_aware <= cutoff:
                result.append(user)
    return result


def get_users_to_auto_delete(db: Session, grace_days: int = 7) -> List[models_db.User]:
    """
    Non-admin users where a deletion warning was sent more than grace_days ago
    and they still have no vehicles.
    """
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=grace_days)
    return (
        db.query(models_db.User)
        .filter(
            models_db.User.is_admin == False,
            models_db.User.account_deletion_reminder_sent_at.isnot(None),
            models_db.User.account_deletion_reminder_sent_at <= cutoff,
            ~models_db.User.vehicles.any(),
        )
        .all()
    )


def clear_account_deletion_reminder(db: Session, user_id: int) -> Optional[models_db.User]:
    """Clear account_deletion_reminder_sent_at so the user is no longer marked for auto-deletion."""
    user = get_user_by_id(db, user_id)
    if user:
        user.account_deletion_reminder_sent_at = None
        db.commit()
        db.refresh(user)
    return user