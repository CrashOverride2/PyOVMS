"""Notification subsystem.

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
from app.notifications.dispatcher import (
    MAX_RECIPIENTS_PER_NOTIFICATION,
    build_dispatch_plan,
    dispatch_notification_to_vehicle,
    shutdown_dispatch_pool,
)
from app.notifications.email_queue import (
    Priority,
    mail_queue,
    queue_email_notification,
    shutdown_email_queue,
)
from app.notifications.errors import (
    InvalidPushTargetError,
    NotificationError,
    OutboundBlockedError,
    TransientDeliveryError,
)
from app.notifications.mail.admin import (
    send_admin_security_notification,
    send_lifecycle_admin_notification,
    send_new_user_admin_notification,
    send_notification_to_all_admins,
)
from app.notifications.mail.user import (
    send_account_deletion_warning_email,
    send_password_reset_email,
    send_unused_vehicle_warning_email,
    send_vehicle_auto_deleted_email,
    send_verification_email,
)
from app.notifications.outbound import (
    assert_safe_outbound_url,
    close_all_sessions,
    pin_outbound_url,
    redact_url,
)
from app.notifications.ratelimit import rate_limiter
from app.notifications.retry import (
    MAX_SEND_ATTEMPTS,
    TRANSIENT_EXCEPTIONS,
    backoff_delay,
    is_transient,
)
from app.notifications.templating import (
    is_template_file,
    template_env,
)

from app.notifications.outbound import _assert_safe_outbound_url as _assert_safe_outbound_url
from app.notifications.outbound import _pin_outbound_url as _pin_outbound_url
from app.notifications.templating import _inline_template_env as _inline_template_env
from app.notifications.templating import _is_template_file as _is_template_file

__all__ = [
    "InvalidPushTargetError",
    "MAX_RECIPIENTS_PER_NOTIFICATION",
    "MAX_SEND_ATTEMPTS",
    "NotificationError",
    "OutboundBlockedError",
    "Priority",
    "TRANSIENT_EXCEPTIONS",
    "TransientDeliveryError",
    "assert_safe_outbound_url",
    "backoff_delay",
    "build_dispatch_plan",
    "close_all_sessions",
    "dispatch_notification_to_vehicle",
    "mail_queue",
    "initialize_apns_client",
    "initialize_firebase_app",
    "is_template_file",
    "is_transient",
    "pin_outbound_url",
    "queue_email_notification",
    "redact_url",
    "rate_limiter",
    "send_account_deletion_warning_email",
    "send_admin_security_notification",
    "send_apns_notification",
    "send_email_notification",
    "send_fcm_notification",
    "send_lifecycle_admin_notification",
    "send_new_user_admin_notification",
    "send_notification_to_all_admins",
    "send_ntfy_notification",
    "send_password_reset_email",
    "send_unified_push_notification",
    "send_unused_vehicle_warning_email",
    "send_vehicle_auto_deleted_email",
    "send_verification_email",
    "shutdown_apns_client",
    "shutdown_dispatch_pool",
    "shutdown_email_queue",
    "template_env",
]
