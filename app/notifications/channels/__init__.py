"""One module per delivery channel.

Every channel exposes a single `send_*` function that returns True on delivery, False on
a failure the caller should just log, and raises InvalidPushTargetError when the target
is permanently gone so the dispatcher can drop the subscription.
"""

from app.notifications.channels.apns import (
    initialize_apns_client,
    send_apns_notification,
    shutdown_apns_client,
)
from app.notifications.channels.fcm import initialize_firebase_app, send_fcm_notification
from app.notifications.channels.ntfy import send_ntfy_notification
from app.notifications.channels.smtp import send_email_notification
from app.notifications.channels.unified_push import send_unified_push_notification

__all__ = [
    "initialize_apns_client",
    "initialize_firebase_app",
    "send_apns_notification",
    "send_email_notification",
    "send_fcm_notification",
    "send_ntfy_notification",
    "send_unified_push_notification",
    "shutdown_apns_client",
]
