"""Mail addressed to a single user: account, credentials and vehicle lifecycle.

All five follow the same shape — resolve a locale, render a .txt/.html pair, hand the
result to the outbound queue — so it is expressed once in `_send_templated_email()`
instead of five times.
"""

import logging
from typing import TYPE_CHECKING, Optional

from app.config import settings
from app.notifications.email_queue import Priority, queue_email_notification
from app.notifications.templating import N_, get_gettext, render_file, template_env

if TYPE_CHECKING:
    from app.models.db import User

logger = logging.getLogger(__name__)


def _send_templated_email(
    recipient_email: str,
    subject_key: str,
    template_stem: str,
    template_vars: dict,
    *,
    locale: Optional[str] = None,
    subject_suffix: str = "",
    subject_prefix: str = "",
    what: str = "email",
    priority: Priority = Priority.LOW,
) -> bool:
    """Render `email/<stem>.txt` and `.html` and hand them to the outbound queue.

    `subject_key` is passed through gettext; the prefix/suffix are not translated
    (they carry ids and the product name).

    Returns whether the message was accepted for delivery, not whether it arrived.
    """
    if not all([settings.EMAIL_HOST, settings.EMAIL_SENDER]):
        logger.debug(f"Email not configured, skipping {what}.")
        return False
    if not template_env:
        logger.error(f"Cannot send {what}: Jinja2 template environment not available.")
        return False

    gettext = get_gettext(locale)
    subject = f"{subject_prefix}{gettext(subject_key)}{subject_suffix}"

    try:
        text_body = render_file(f"email/{template_stem}.txt", {"_": gettext, **template_vars})
        html_body = render_file(f"email/{template_stem}.html", {"_": gettext, **template_vars})
    except Exception as e:
        logger.error(f"Error rendering {what} template '{template_stem}': {e}", exc_info=True)
        return False

    return queue_email_notification(recipient_email, subject, text_body, html_body, priority)


def send_verification_email(user: "User", verification_link: str) -> bool:
    return _send_templated_email(
        user.email,
        N_("Verify Your PyOVMS Account"),
        "verification_body",
        {
            "display_name": user.full_name or user.username,
            "verification_link": verification_link,
            "server_base_url": settings.SERVER_BASE_URL,
            "valid_hours": settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS,
        },
        locale="en",
        subject_prefix="✅ ",
        what="verification email",
        # Somebody just submitted the registration form and is waiting for this.
        priority=Priority.HIGH,
    )


def send_password_reset_email(recipient_email: str, display_name: str, user_language: str, reset_link: str) -> bool:
    """
    Send a password reset email to the user.

    Args:
        recipient_email: The email address to send to
        display_name: The display name for the greeting
        user_language: The user's preferred language
        reset_link: The full URL for the password reset link

    Returns:
        True if the email was accepted by the outbound queue, False otherwise
    """
    return _send_templated_email(
        recipient_email,
        N_("Password Reset Request"),
        "password_reset_body",
        {
            "display_name": display_name,
            "reset_link": reset_link,
            "server_base_url": settings.SERVER_BASE_URL,
            "valid_hours": settings.PASSWORD_RESET_TOKEN_EXPIRE_HOURS,
        },
        # get_gettext() falls back to the default locale for anything unsupported.
        locale=user_language,
        subject_suffix=" - PyOVMS",
        what="password reset email",
        # Same: a person is sitting in front of a browser waiting for the link.
        priority=Priority.HIGH,
    )


def send_unused_vehicle_warning_email(vehicle_id: str, vehicle_name: Optional[str], last_seen: str, owner_email: str, owner_display_name: str) -> bool:
    """Send an inactivity warning email to the vehicle owner."""
    return _send_templated_email(
        owner_email,
        N_("Inactive Vehicle Notice"),
        "unused_vehicle_warning",
        {
            "display_name": owner_display_name,
            "vehicle_id": vehicle_id,
            "vehicle_name": vehicle_name,
            "last_seen": last_seen,
            "server_base_url": settings.SERVER_BASE_URL,
        },
        subject_suffix=f": {vehicle_id} - PyOVMS",
        what="unused vehicle warning",
    )


def send_vehicle_auto_deleted_email(vehicle_id: str, vehicle_name: Optional[str], owner_email: str, owner_display_name: str) -> bool:
    """Notify the vehicle owner that their vehicle was automatically deleted."""
    return _send_templated_email(
        owner_email,
        N_("Vehicle Removed"),
        "vehicle_auto_deleted",
        {
            "display_name": owner_display_name,
            "vehicle_id": vehicle_id,
            "vehicle_name": vehicle_name,
            "server_base_url": settings.SERVER_BASE_URL,
        },
        subject_suffix=f": {vehicle_id} - PyOVMS",
        what="vehicle auto-deleted notification",
    )


def send_account_deletion_warning_email(user_email: str, user_display_name: str) -> bool:
    """Send an account deletion warning to an inactive user with no vehicles."""
    return _send_templated_email(
        user_email,
        N_("Account Deletion Notice"),
        "account_deletion_warning",
        {
            "display_name": user_display_name,
            "server_base_url": settings.SERVER_BASE_URL,
        },
        subject_suffix=" - PyOVMS",
        what="account deletion warning",
    )
