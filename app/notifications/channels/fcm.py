"""Firebase Cloud Messaging delivery (Android, and iOS when APNS_DELIVERY_METHOD=fcm)."""

import logging
import threading
from pathlib import Path
from typing import Optional

import firebase_admin
from firebase_admin import credentials, messaging

from app.config import settings
from app.notifications.errors import InvalidPushTargetError
from app.notifications.retry import TRANSIENT_EXCEPTIONS

logger = logging.getLogger(__name__)

_firebase_app_initialized = False
# initialize_firebase_app() is called from bootstrap, but a second caller on another
# thread would race the flag and call firebase_admin.initialize_app() twice, which
# raises. Cheap to make it a one-shot.
_init_lock = threading.Lock()


def initialize_firebase_app():
    global _firebase_app_initialized
    if _firebase_app_initialized:
        return

    with _init_lock:
        if _firebase_app_initialized:
            return

        if not settings.FCM_CREDENTIALS_PATH:
            logger.info("FCM_CREDENTIALS_PATH not set. FCM notifications disabled.")
            return

        cred_path = Path(settings.FCM_CREDENTIALS_PATH)
        if not cred_path.exists():
            logger.warning(f"FCM_CREDENTIALS_PATH ('{cred_path}') does not exist. FCM notifications disabled.")
            return

        try:
            cred = credentials.Certificate(str(cred_path))
            firebase_admin.initialize_app(cred)
            _firebase_app_initialized = True
            logger.info("Firebase Admin SDK initialized successfully for FCM.")
        except Exception as e:
            logger.error(f"Failed to initialize Firebase Admin SDK: {e}", exc_info=True)


def is_available() -> bool:
    return _firebase_app_initialized


def send_fcm_notification(
    device_token: str,
    title: str,
    body: str,
    data: Optional[dict] = None,
    is_apns_token: bool = False
) -> bool:
    if not _firebase_app_initialized:
        logger.warning("Firebase Admin SDK not initialized. Skipping FCM notification.")
        return False
    if not device_token:
        logger.warning("FCM device token not provided. Skipping notification.")
        return False

    message_args = {
        "token": device_token,
        "data": data if data else {}
    }

    if is_apns_token:
        payload_data = data if data else {}
        apns_payload = messaging.APNSPayload(
            aps=messaging.Aps(
                alert=messaging.ApsAlert(title=title, body=body),
                sound="default",
                badge=1,
            ),
            **payload_data
        )
        message_args["apns"] = messaging.APNSConfig(payload=apns_payload)
        logger.debug(f"FCM: Assembling message for APNs token {device_token[:10]}...")
    else:
        message_args["notification"] = messaging.Notification(
            title=title,
            body=body
        )
        logger.debug(f"FCM: Assembling message for FCM token {device_token[:10]}...")

    message = messaging.Message(**message_args)

    try:
        response = messaging.send(message)
        logger.info(f"FCM notification sent successfully to token starting with {device_token[:10]}...: {response}")
        return True
    except (messaging.UnregisteredError, messaging.SenderIdMismatchError) as e:
        raise InvalidPushTargetError(f"FCM token {device_token[:10]}... is invalid/unregistered: {e}") from e
    except TRANSIENT_EXCEPTIONS:
        raise  # rescheduled by the dispatcher, which does not block a worker to wait
    except firebase_admin.exceptions.InvalidArgumentError as e:
        # Can mean a malformed token OR a malformed payload - not retryable either way,
        # but not proof of a dead subscription, so do not escalate to InvalidPushTargetError.
        logger.warning(f"FCM rejected message for token {device_token[:10]}...: {e}. Will not retry.")
        return False
    except Exception as e:
        logger.error(f"FCM send failed for token {device_token[:10]}...: {e}")
        return False
