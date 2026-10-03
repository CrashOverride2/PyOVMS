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
    is_apns_token: bool = False,
    badge: int = 1,
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

    # The APNs side of the message. "mutable-content": 1 runs the iOS app's Notification
    # Service Extension (it masks a SIM PIN in the text and records the push for the
    # app's history); it needs an alert, so a silent push must never carry it. The alert
    # is stated here rather than left for FCM to derive from `notification`: identical
    # text, and nothing depends on how FCM merges the two.
    aps = messaging.Aps(
        alert=messaging.ApsAlert(title=title, body=body),
        sound="default",
        badge=badge,
        mutable_content=True,
    )

    if is_apns_token:
        payload_data = data if data else {}
        apns_payload = messaging.APNSPayload(aps=aps, **payload_data)
        message_args["apns"] = messaging.APNSConfig(payload=apns_payload)
        logger.debug(f"FCM: Assembling message for APNs token {device_token[:10]}...")
    else:
        # An FCM token does not say which platform it belongs to: the app registers
        # iPhones and Android phones alike as push_type 'fcm'. So the message carries
        # both overrides and FCM applies the one for the token's platform. `data` stays
        # in message.data, which FCM places at the top level of the APNs userInfo —
        # where the iOS extension reads vehicle_id, timestamp and notification_type.
        message_args["notification"] = messaging.Notification(
            title=title,
            body=body
        )
        message_args["apns"] = messaging.APNSConfig(payload=messaging.APNSPayload(aps=aps))
        message_args["android"] = messaging.AndroidConfig(
            notification=messaging.AndroidNotification(notification_count=badge),
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


# The data a badge reset carries, so the app can tell it from a notification.
BADGE_RESET_DATA = {"type": "badge_reset"}


def send_fcm_badge_reset(device_token: str, is_apns_token: bool = False) -> bool:
    """Tell one device that the account's unread count is back to 0.

    Sent to a user's *other* devices when one of them opens the app. Nothing is shown:
    on iOS it is a badge-only APNs push (`aps.badge = 0`, no alert, no sound and no
    `mutable-content`, so the extension does not run), on Android a data message the
    app's background handler answers by cancelling the notifications it shows — the
    launcher's dot and count are those notifications.

    Time to live 0 on both sides: delivered now or dropped. A reset held while the
    device is offline could otherwise arrive after a newer alert and clear that one.
    High priority on Android, because a dozing phone is exactly the one whose dot is
    still up when it is picked up. FCM deprioritizes an app whose high-priority messages
    form a *pattern* of showing nothing (docs: android/message-priority); a reset follows
    at most once per batch of visible notifications, so it never becomes one. Never
    retried by the dispatcher either (`DispatchTarget.retry`): a resend after a
    transient error would undo exactly what TTL 0 is for.
    """
    if not _firebase_app_initialized:
        logger.warning("Firebase Admin SDK not initialized. Skipping FCM badge reset.")
        return False
    if not device_token:
        return False

    apns = messaging.APNSConfig(
        headers={"apns-push-type": "alert", "apns-priority": "10", "apns-expiration": "0"},
        payload=messaging.APNSPayload(
            aps=messaging.Aps(badge=0),
            **(BADGE_RESET_DATA if is_apns_token else {}),
        ),
    )
    message_args = {"token": device_token, "apns": apns}
    if not is_apns_token:
        message_args["data"] = dict(BADGE_RESET_DATA)
        message_args["android"] = messaging.AndroidConfig(priority="high", ttl=0)

    try:
        messaging.send(messaging.Message(**message_args))
        logger.info(f"FCM badge reset sent to token starting with {device_token[:10]}...")
        return True
    except (messaging.UnregisteredError, messaging.SenderIdMismatchError) as e:
        raise InvalidPushTargetError(f"FCM token {device_token[:10]}... is invalid/unregistered: {e}") from e
    except TRANSIENT_EXCEPTIONS:
        raise
    except firebase_admin.exceptions.InvalidArgumentError as e:
        logger.warning(f"FCM rejected badge reset for token {device_token[:10]}...: {e}. Will not retry.")
        return False
    except Exception as e:
        logger.error(f"FCM badge reset failed for token {device_token[:10]}...: {e}")
        return False
