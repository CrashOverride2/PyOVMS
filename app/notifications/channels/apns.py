"""Apple Push Notification service delivery, via the direct HTTP/2 provider client."""

import logging
import threading
import time
from typing import Optional

from app.config import settings
from app.notifications.errors import InvalidPushTargetError
from app.notifications.retry import TRANSIENT_EXCEPTIONS
from app.services.apns_client import ApnsInvalidTokenError, build_client_from_settings

logger = logging.getLogger(__name__)

_apns_client: Optional[object] = None

APNS_ALERT_LIFETIME_SECONDS = 24 * 3600
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

    # mutable-content lets the app's Notification Service Extension run before the
    # alert is shown (it masks a SIM PIN in the text and records the push for the
    # app's history). It needs an alert, so a silent push must never carry it. The data
    # keys stay at the top level of the payload: that is where the extension reads them.
    payload = {
        "aps": {
            "alert": {"title": title, "body": body},
            "sound": "default",
            "badge": badge,
            "mutable-content": 1,
        },
        **(data or {}),
    }

    try:
        client.send(device_token, payload, topic=settings.APNS_TOPIC,
                    expiration=int(time.time()) + APNS_ALERT_LIFETIME_SECONDS)
        logger.info(f"APNs notification sent successfully to token starting with {device_token[:10]}...")
        return True
    except ApnsInvalidTokenError as e:
        raise InvalidPushTargetError(f"APNs token {device_token[:10]}... is invalid/unregistered: {e}") from e
    except TRANSIENT_EXCEPTIONS:
        raise  # rescheduled by the dispatcher, which does not block a worker to wait
    except Exception as e:
        logger.error(f"APNs send failed for token {device_token[:10]}...: {e}")
        return False


def send_apns_badge_reset(device_token: str) -> bool:
    """A badge-only push: sets the icon to 0 and shows nothing.

    No alert, so no `mutable-content` either; expiration 0, so a reset that cannot be
    delivered now is dropped rather than arriving after a newer alert.
    """
    client = _apns_client
    if not client or not device_token:
        return False
    payload = {"aps": {"badge": 0}, "type": "badge_reset"}
    try:
        client.send(device_token, payload, topic=settings.APNS_TOPIC,
                    push_type="alert", priority=10, expiration=0)
        logger.info(f"APNs badge reset sent to token starting with {device_token[:10]}...")
        return True
    except ApnsInvalidTokenError as e:
        raise InvalidPushTargetError(f"APNs token {device_token[:10]}... is invalid/unregistered: {e}") from e
    except TRANSIENT_EXCEPTIONS:
        raise
    except Exception as e:
        logger.error(f"APNs badge reset failed for token {device_token[:10]}...: {e}")
        return False
