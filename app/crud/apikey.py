from sqlalchemy.orm import Session
from sqlalchemy import desc
import datetime
import secrets
import hashlib
from enum import Enum
from typing import Optional, List, Tuple

from app.models import db as models_db
from app.services.mqtt_auth_manager import mqtt_manager
from app.config import settings
import logging

logger = logging.getLogger(__name__)

def _generate_api_key_secure() -> str:
    return secrets.token_urlsafe(32)

def _hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode('utf-8')).hexdigest()

# Name prefixes the server manages itself. They must never be accepted from user
# input: behaviour is attached to them (quota exemption, "don't register this with the
# broker", sliding expiry), and that behaviour used to be derived from the name alone —
# so a user who named their key "temp-karto-delete-x" got unlimited keys, each costing
# a 100k-iteration PBKDF2 hash plus a full rewrite of the Mosquitto password and ACL
# files. Callers now state their intent explicitly; the prefixes are what makes a name
# trustworthy as a server-side marker afterwards.
DEVICE_KEY_NAME_PREFIX = "device-"

# Keys the server creates for its own plumbing. The user never asked for them, cannot
# act on them and they disappear on their own, so they are hidden from the profile
# page and excluded from the quota. A device key is deliberately NOT in this list:
# it represents a phone the user set up, and being able to see and revoke it is the
# point. `ws-ticket-` used to be here too — the one-shot key a page exchanged for a
# WebSocket; the socket is authenticated by the session cookie now, and the migration
# that retired the ticket deleted the rows.
INTERNAL_KEY_NAME_PREFIXES = ("temp-karto-delete-",)

RESERVED_KEY_NAME_PREFIXES = INTERNAL_KEY_NAME_PREFIXES + (DEVICE_KEY_NAME_PREFIX,)

# A device key expires this long after it was last *used*, not after it was created.
# See slide_device_key_expiry() for why.
DEVICE_KEY_IDLE_VALIDITY = datetime.timedelta(days=180)

# Only rewrite the expiry when it would move by more than this, so a busy client does
# not turn every request into a column update.
_EXPIRY_SLIDE_GRANULARITY = datetime.timedelta(days=1)


def is_reserved_key_name(name: str) -> bool:
    """True if `name` is reserved for server-generated keys and must be rejected."""
    return name.strip().lower().startswith(RESERVED_KEY_NAME_PREFIXES)


def is_internal_key_name(name: Optional[str]) -> bool:
    """True for server plumbing keys (the Karto deletion key)."""
    return bool(name) and name.startswith(INTERNAL_KEY_NAME_PREFIXES)


def is_device_key(api_key: models_db.ApiKey) -> bool:
    """
    True for keys minted by the device-provisioning endpoint.

    Reads the column, never the name. Inferring it from DEVICE_KEY_NAME_PREFIX would
    retroactively reclassify keys that already existed before that prefix was
    reserved — someone's hand-made "device-tesla" key with a deliberate 30-day expiry
    would have started renewing itself to 180 days.
    """
    return bool(getattr(api_key, "is_device_key", False))


class KeyPurpose(str, Enum):
    """
    Why a key is being created. Decides quota, naming rules and expiry behaviour.

    This replaced a pair of booleans that had already grown one invalid combination
    between them and would have needed a third for the device flag.
    """

    # Requested by a person through the profile page or the JSON API.
    USER = "user"
    # Provisioned for a mobile device. Counts against the quota exactly like a USER
    # key — it is user-requested — but the server picks the name and the expiry slides.
    DEVICE = "device"
    # The server's own plumbing: WebSocket tickets, the Karto deletion key. Exempt
    # from the quota, hidden from the profile page, short-lived.
    INTERNAL = "internal"


def create_api_key(
    db: Session,
    user_id: int,
    name: str,
    expires_delta: Optional[datetime.timedelta] = None,
    purpose: KeyPurpose = KeyPurpose.USER,
) -> Tuple[models_db.ApiKey, str]:
    """
    Create an API key for a user.

    `purpose` decides three things at once and must only ever be set by server code —
    never from a request parameter. See KeyPurpose for what each value means.
    """
    if purpose == KeyPurpose.USER and is_reserved_key_name(name):
        raise ValueError("This API key name is reserved for internal use. Please choose another name.")

    if purpose != KeyPurpose.INTERNAL:
        # Exclude the server's own plumbing from the count. The exemption used to be
        # one-sided: creating an internal key skipped the check, but the key still
        # occupied a slot afterwards, and the user's quota for real keys shrank while
        # it lived.
        active_key_count = db.query(models_db.ApiKey).filter(
            models_db.ApiKey.user_id == user_id,
            models_db.ApiKey.is_active == True,
            *[~models_db.ApiKey.name.startswith(prefix) for prefix in INTERNAL_KEY_NAME_PREFIXES],
        ).count()
        if active_key_count >= settings.MAX_API_KEYS_PER_USER:
            raise ValueError(f"API key limit reached ({settings.MAX_API_KEYS_PER_USER} active keys max).")

    plain_key = _generate_api_key_secure()
    hashed_key = _hash_api_key(plain_key)
    key_prefix = plain_key[:8]

    expires_at_datetime = None
    if expires_delta:
        expires_at_datetime = datetime.datetime.now(datetime.timezone.utc) + expires_delta

    db_api_key = models_db.ApiKey(
        key_prefix=key_prefix,
        hashed_key=hashed_key,
        user_id=user_id,
        name=name,
        created_at=datetime.datetime.now(datetime.timezone.utc),
        expires_at=expires_at_datetime,
        is_active=True,
        is_device_key=(purpose == KeyPurpose.DEVICE),
    )
    db.add(db_api_key)
    db.commit()
    db.refresh(db_api_key)

    if mqtt_manager.is_enabled():
        mqtt_manager.add_api_key_user(db_api_key.key_prefix, plain_key)
        mqtt_manager.regenerate_acl_file(db)

    return db_api_key, plain_key

def get_api_key_by_raw_key(db: Session, raw_key: str) -> Optional[models_db.ApiKey]:
    hashed_key_to_check = _hash_api_key(raw_key)
    return db.query(models_db.ApiKey).filter(models_db.ApiKey.hashed_key == hashed_key_to_check).first()

def get_api_keys_for_user(
    db: Session, user_id: int, include_internal: bool = False
) -> List[models_db.ApiKey]:
    """
    Keys belonging to a user, newest first.

    Server plumbing is hidden by default: nothing useful can be done with the Karto
    deletion key from that page, and it disappears on its own.

    Device keys stay visible on purpose: each one is a phone the user set up, and
    seeing and revoking them is exactly what that list is for.
    """
    query = db.query(models_db.ApiKey).filter(models_db.ApiKey.user_id == user_id)
    if not include_internal:
        for prefix in INTERNAL_KEY_NAME_PREFIXES:
            query = query.filter(~models_db.ApiKey.name.startswith(prefix))
    return query.order_by(desc(models_db.ApiKey.created_at)).all()

def get_api_key_by_id_and_user(db: Session, api_key_id: int, user_id: int) -> Optional[models_db.ApiKey]:
    return db.query(models_db.ApiKey).filter(models_db.ApiKey.id == api_key_id, models_db.ApiKey.user_id == user_id).first()

def update_api_key_last_used(db: Session, api_key_db: models_db.ApiKey) -> models_db.ApiKey:
    now = datetime.datetime.now(datetime.timezone.utc)
    api_key_db.last_used_at = now
    slide_device_key_expiry(api_key_db, now=now)
    db.commit()
    db.refresh(api_key_db)
    return api_key_db


def slide_device_key_expiry(
    api_key_db: models_db.ApiKey,
    now: Optional[datetime.datetime] = None,
) -> bool:
    """
    Push a device key's expiry out to DEVICE_KEY_IDLE_VALIDITY from now. Returns True
    if it changed.

    Device keys expire relative to their *last use*, not their creation. A fixed
    lifetime from creation would mean the app simply stops working after six months
    and demands a full re-setup — password and 2FA code — even though the phone was in
    daily use the whole time. Worse, the key is also the MQTT password, so expiry
    breaks push notifications and live data at the same moment, and hourly
    housekeeping removes the broker account too.

    Sliding on use keeps the property that made the expiry worth having — a phone that
    is sold, wiped, or has the app uninstalled stops holding valid credentials — while
    a device that is actually in use never notices. Only device keys slide: an expiry a
    user typed into the profile page is a deliberate statement and must be honoured
    literally.

    The caller is responsible for committing.
    """
    if not is_device_key(api_key_db) or api_key_db.expires_at is None:
        return False

    now = now or datetime.datetime.now(datetime.timezone.utc)
    target = now + DEVICE_KEY_IDLE_VALIDITY

    current = api_key_db.expires_at
    if current is not None and current.tzinfo is None:
        # SQLite and MySQL hand back naive datetimes; they are stored as UTC.
        current = current.replace(tzinfo=datetime.timezone.utc)

    if current is not None and target - current < _EXPIRY_SLIDE_GRANULARITY:
        return False

    api_key_db.expires_at = target
    return True

def delete_api_key_by_id_and_user(db: Session, api_key_id: int, user_id: int) -> Optional[models_db.ApiKey]:
    api_key_db = get_api_key_by_id_and_user(db, api_key_id, user_id)
    if api_key_db:
        key_prefix_to_remove = api_key_db.key_prefix
        db.delete(api_key_db)
        db.commit()

        if mqtt_manager.is_enabled():
            mqtt_manager.remove_api_key_user(key_prefix_to_remove)
            mqtt_manager.regenerate_acl_file(db)
        return api_key_db
    return None

def delete_api_keys_by_name_for_user(db: Session, user_id: int, name: str) -> int:
    """Deletes all API keys with a specific name for a given user and cleans up MQTT."""
    keys_to_delete_query = db.query(models_db.ApiKey).filter_by(user_id=user_id, name=name)
    keys_to_delete = keys_to_delete_query.all()

    if not keys_to_delete:
        return 0

    key_prefixes_to_remove = [key.key_prefix for key in keys_to_delete]
    num_deleted = keys_to_delete_query.delete(synchronize_session=False)
    db.commit()

    if mqtt_manager.is_enabled() and key_prefixes_to_remove:
        logger.info(f"MQTT: Removing {len(key_prefixes_to_remove)} internal API key users by name '{name}': {key_prefixes_to_remove}")
        for prefix in key_prefixes_to_remove:
            mqtt_manager.remove_api_key_user(prefix)
        mqtt_manager.regenerate_acl_file(db)

    return num_deleted

def revoke_device_keys_for_user(db: Session, user_id: int) -> int:
    """
    Delete every provisioned device key for a user and drop its broker account.
    Returns the number revoked.

    Called from the password reset path. Bumping token_version there kills the JWT
    sessions, but a device key is an API key and was untouched by that — so an
    attacker who had provisioned one through /api/v1/auth/device-token kept full
    access straight through the reset. Worse, that key slides its own expiry forward
    on every use, so the access never lapsed on its own either: the one action a user
    takes to recover their account did not actually remove the intruder.

    Only device keys. A key the user created by hand may be wired into a home
    automation setup or a script, and silently breaking those on a routine password
    change would train people not to reset. Device keys have a re-provisioning flow
    already — the app fetches a new one on next start, exactly as it does after an
    expiry — so revoking them costs the legitimate user nothing but a re-login.
    """
    device_keys = db.query(models_db.ApiKey).filter(
        models_db.ApiKey.user_id == user_id,
        models_db.ApiKey.is_device_key == True,
    ).all()
    if not device_keys:
        return 0

    key_prefixes = [key.key_prefix for key in device_keys]
    for key in device_keys:
        db.delete(key)
    db.commit()

    if mqtt_manager.is_enabled():
        logger.info(f"MQTT: Revoking {len(key_prefixes)} device key(s) for user {user_id}: {key_prefixes}")
        for prefix in key_prefixes:
            mqtt_manager.remove_api_key_user(prefix)
        mqtt_manager.regenerate_acl_file(db)

    return len(device_keys)


def delete_expired_api_keys(db: Session) -> int:
    """Deletes API keys that are past their expiry date AND are already inactive."""
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    num_deleted = db.query(models_db.ApiKey).filter(
        models_db.ApiKey.is_active == False,
        models_db.ApiKey.expires_at != None,
        models_db.ApiKey.expires_at < now_utc
    ).delete(synchronize_session=False)
    db.commit()
    if num_deleted > 0:
        logger.info(f"Housekeeping: Permanently deleted {num_deleted} inactive and expired API keys from the database.")
    return num_deleted

def deactivate_and_remove_expired_api_keys_from_mqtt(db: Session) -> int:
    """Finds expired but still active API keys, deactivates them, and removes from MQTT."""
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    expired_keys = db.query(models_db.ApiKey).filter(
        models_db.ApiKey.is_active == True,
        models_db.ApiKey.expires_at != None,
        models_db.ApiKey.expires_at < now_utc
    ).all()
    
    if not expired_keys:
        return 0

    key_prefixes_to_remove = [key.key_prefix for key in expired_keys]
    for key in expired_keys:
        key.is_active = False
    db.commit()

    if mqtt_manager.is_enabled() and key_prefixes_to_remove:
        logger.info(f"MQTT: Deactivating and removing {len(key_prefixes_to_remove)} expired API key users: {key_prefixes_to_remove}")
        for prefix in key_prefixes_to_remove:
            mqtt_manager.remove_api_key_user(prefix)
        mqtt_manager.regenerate_acl_file(db)

    return len(expired_keys)
