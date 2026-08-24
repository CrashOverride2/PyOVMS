"""Composed e-mail messages: what gets said, to whom, in which language.

Split from the channels below it — `channels/smtp.py` knows how to deliver a message,
these modules know which template and which recipient set a given event calls for.
"""

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

__all__ = [
    "send_account_deletion_warning_email",
    "send_admin_security_notification",
    "send_lifecycle_admin_notification",
    "send_new_user_admin_notification",
    "send_notification_to_all_admins",
    "send_password_reset_email",
    "send_unused_vehicle_warning_email",
    "send_vehicle_auto_deleted_email",
    "send_verification_email",
]
