import datetime
import logging

from sqlalchemy.orm import Session

from app.models.db import PushSubscription
from app.utils.crypto import encrypt_data

logger = logging.getLogger(__name__)

_MOBILE_TYPES = {'fcm', 'up'}

# Hard ceiling on rows per vehicle. `device_id` is chosen by the client, so a device
# that reinstalls with a fresh identifier — or a caller doing it on purpose — otherwise
# adds a row every time, forever. The notification fan-out is separately capped at
# MAX_RECIPIENTS_PER_NOTIFICATION, so rows beyond that ceiling could never be delivered
# to anyway; they only ever cost storage and query time.
MAX_SUBSCRIPTIONS_PER_VEHICLE = 50


def _evict_oldest_beyond_cap(db: Session, vehicle_id_fk: int) -> None:
    """Keep only the MAX_SUBSCRIPTIONS_PER_VEHICLE most recent rows for a vehicle."""
    stale_ids = [
        row_id for (row_id,) in db.query(PushSubscription.id)
        .filter(PushSubscription.vehicle_id_fk == vehicle_id_fk)
        .order_by(PushSubscription.created_at.desc(), PushSubscription.id.desc())
        .offset(MAX_SUBSCRIPTIONS_PER_VEHICLE)
        .all()
    ]
    if not stale_ids:
        return
    db.query(PushSubscription).filter(PushSubscription.id.in_(stale_ids)).delete(
        synchronize_session=False
    )
    logger.warning(
        "Vehicle %s exceeded %d push subscriptions; dropped the %d oldest.",
        vehicle_id_fk, MAX_SUBSCRIPTIONS_PER_VEHICLE, len(stale_ids),
    )


def upsert_subscription(db: Session, vehicle_id_fk: int, device_id: str, push_type: str, endpoint: str) -> PushSubscription:
    """Insert or update a push subscription. When a mobile push type (fcm/up) is registered,
    any conflicting mobile subscription for the same device is removed first."""
    if push_type in _MOBILE_TYPES:
        # Remove the other mobile type for this device (prevents FCM+UP duplicates)
        conflicting = _MOBILE_TYPES - {push_type}
        db.query(PushSubscription).filter(
            PushSubscription.vehicle_id_fk == vehicle_id_fk,
            PushSubscription.device_id == device_id,
            PushSubscription.push_type.in_(conflicting),
        ).delete(synchronize_session=False)

    existing = db.query(PushSubscription).filter(
        PushSubscription.vehicle_id_fk == vehicle_id_fk,
        PushSubscription.device_id == device_id,
        PushSubscription.push_type == push_type,
    ).first()

    if existing:
        existing.endpoint = endpoint
        existing.updated_at = datetime.datetime.now(datetime.timezone.utc)
        db.flush()
        return existing

    sub = PushSubscription(
        vehicle_id_fk=vehicle_id_fk,
        device_id=device_id,
        push_type=push_type,
        endpoint=endpoint,
    )
    db.add(sub)
    db.flush()
    _evict_oldest_beyond_cap(db, vehicle_id_fk)
    return sub


def get_subscriptions_for_vehicle(
    db: Session, vehicle_id_fk: int, limit: int | None = None
) -> list[PushSubscription]:
    """Subscriptions for a vehicle, most recently registered first.

    The ordering is part of the contract: the dispatcher delivers to the newest N and
    drops the rest, and doing that in SQL is what keeps a vehicle that accumulated
    device registrations from loading all of them on every notification.
    """
    query = (
        db.query(PushSubscription)
        .filter(PushSubscription.vehicle_id_fk == vehicle_id_fk)
        .order_by(PushSubscription.created_at.desc(), PushSubscription.id.desc())
    )
    if limit is not None:
        query = query.limit(limit)
    return query.all()


def get_subscriptions_by_type(db: Session, vehicle_id_fk: int, push_type: str) -> list[PushSubscription]:
    return db.query(PushSubscription).filter(
        PushSubscription.vehicle_id_fk == vehicle_id_fk,
        PushSubscription.push_type == push_type,
    ).all()


def add_manual_ntfy(
    db: Session,
    vehicle_id_fk: int,
    topic: str,
    server_url: str | None = None,
    auth_method: str | None = None,
    auth_token: str | None = None,
    auth_user: str | None = None,
    auth_password: str | None = None,
    auth_query_param_name: str | None = None,
) -> PushSubscription:
    """Upsert a manually configured ntfy subscription (keyed by topic)."""
    device_id = topic[:255]
    existing = db.query(PushSubscription).filter(
        PushSubscription.vehicle_id_fk == vehicle_id_fk,
        PushSubscription.device_id == device_id,
        PushSubscription.push_type == 'ntfy',
    ).first()
    enc_token = encrypt_data(auth_token) if auth_token else None
    enc_password = encrypt_data(auth_password) if auth_password else None

    if existing:
        existing.endpoint = topic
        existing.ntfy_server_url = server_url
        existing.ntfy_auth_method = auth_method
        existing.ntfy_auth_token = enc_token
        existing.ntfy_auth_user = auth_user
        existing.ntfy_auth_password = enc_password
        existing.ntfy_auth_query_param_name = auth_query_param_name
        existing.updated_at = datetime.datetime.now(datetime.timezone.utc)
        db.flush()
        return existing
    sub = PushSubscription(
        vehicle_id_fk=vehicle_id_fk,
        device_id=device_id,
        push_type='ntfy',
        endpoint=topic,
        ntfy_server_url=server_url,
        ntfy_auth_method=auth_method,
        ntfy_auth_token=enc_token,
        ntfy_auth_user=auth_user,
        ntfy_auth_password=enc_password,
        ntfy_auth_query_param_name=auth_query_param_name,
    )
    db.add(sub)
    db.flush()
    _evict_oldest_beyond_cap(db, vehicle_id_fk)
    return sub


def add_manual_email(db: Session, vehicle_id_fk: int, email_address: str) -> PushSubscription:
    """Upsert a manually configured e-mail recipient (keyed by address)."""
    device_id = email_address[:255]
    existing = db.query(PushSubscription).filter(
        PushSubscription.vehicle_id_fk == vehicle_id_fk,
        PushSubscription.device_id == device_id,
        PushSubscription.push_type == 'email',
    ).first()
    if existing:
        existing.endpoint = email_address
        existing.updated_at = datetime.datetime.now(datetime.timezone.utc)
        db.flush()
        return existing
    sub = PushSubscription(
        vehicle_id_fk=vehicle_id_fk,
        device_id=device_id,
        push_type='email',
        endpoint=email_address,
    )
    db.add(sub)
    db.flush()
    _evict_oldest_beyond_cap(db, vehicle_id_fk)
    return sub


def delete_subscription(db: Session, subscription_id: int, vehicle_id_fk: int) -> bool:
    """Delete a push subscription by ID, scoped to a vehicle. Returns True if deleted."""
    deleted = db.query(PushSubscription).filter(
        PushSubscription.id == subscription_id,
        PushSubscription.vehicle_id_fk == vehicle_id_fk,
    ).delete(synchronize_session=False)
    db.commit()
    return deleted > 0
