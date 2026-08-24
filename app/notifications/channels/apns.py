"""Apple Push Notification service delivery, via the direct HTTP/2 provider client."""

import logging
import threading
from typing import Optional

from app.config import settings
from app.notifications.errors import InvalidPushTargetError
from app.notifications.retry import TRANSIENT_EXCEPTIONS
from app.services.apns_client import ApnsInvalidTokenError, build_client_from_settings

logger = logging.getLogger(__name__)

_apns_client: Optional[object] = None
_client_lock = threading.Lock()


def initialize_apns_client():
    global _apns_client
    if _apns_client:
        return
    with _client_lock:
        if _apns_client:
            return
        _apns_client = build_client_from_settings()


def shutdown_apns_client():
    """Closes the pooled HTTP/2 connection to APNs."""
    global _apns_client
    with _client_lock:
        if _apns_client:
            _apns_client.close()
            _apns_client = None


def is_available() -> bool:
    return _apns_client is not None


def send_apns_notification(device_token: str, title: str, body: str, data: Optional[dict] = None, badge: int = 1) -> bool:
    client = _apns_client
    if not client:
        logger.warning("APNs client not initialized. Skipping APNs notification.")
        return False
    if not device_token:
        logger.warning("APNs device token not provided. Skipping notification.")
        return False

    payload = {
        "aps": {
            "alert": {"title": title, "body": body},
            "sound": "default",
            "badge": badge,
        },
        **(data or {}),
    }

    try:
        client.send(device_token, payload, topic=settings.APNS_TOPIC)
        logger.info(f"APNs notification sent successfully to token starting with {device_token[:10]}...")
        return True
    except ApnsInvalidTokenError as e:
        raise InvalidPushTargetError(f"APNs token {device_token[:10]}... is invalid/unregistered: {e}") from e
    except TRANSIENT_EXCEPTIONS:
        raise  # rescheduled by the dispatcher, which does not block a worker to wait
    except Exception as e:
        logger.error(f"APNs send failed for token {device_token[:10]}...: {e}")
        return False
