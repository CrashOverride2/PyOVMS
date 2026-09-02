"""Mail addressed to the server's administrators.

Everything here fans out to "all active admins", which is why it is separated from the
user-addressed mail: the failure mode that matters is one bad admin row silently taking
down the whole notification, and that is handled once, here.
"""

import logging
from typing import TYPE_CHECKING, List, Optional

from app.config import settings
from app.notifications.email_queue import Priority, queue_email_notification
from app.notifications.templating import N_, get_gettext, render_source, template_env
from app.utils.timestamps import as_utc

if TYPE_CHECKING:
    from app.models.db import User

logger = logging.getLogger(__name__)

# Subjects that live inside Jinja template *strings* in Python modules. The `{{ _('…') }}`
# in them is resolved at render time, but the file is scanned as Python, so the extractor
# never sees the call and the msgid never reaches the catalogue — the body of the mail
# arrives translated and the subject stays English. Repeating them under N_() is what
# puts them in messages.pot; `tests/test_mail_translations.py` fails if the two drift.
UNTRANSLATED_SUBJECT_MSGIDS = (
    N_("New User Registration on PyOVMS"),
    N_("OVMS Security Alert: IP Blocked"),
)


def _email_is_configured(notification_type: str) -> bool:
    if not all([settings.EMAIL_HOST, settings.EMAIL_SENDER]):
        logger.debug(f"Email not configured, skipping admin {notification_type}")
        return False
    if not template_env:
        logger.error(f"Cannot send {notification_type}: Jinja2 template environment not available.")
        return False
    return True


def _load_admin_recipients() -> Optional[List[tuple]]:
    """Return (username, email, display_name) for every active admin with an address.

    The session is opened and closed here, before any SMTP happens: the previous version
    held it open across every send, so a slow mail server pinned a pooled database
    connection for the duration of the fan-out.
    """
    from app.database import SessionLocal
    from app.models.db import User

    db = SessionLocal()
    try:
        admin_users = db.query(User).filter(
            User.is_admin == True,  # noqa: E712 - SQLAlchemy column comparison
            User.is_active == True,  # noqa: E712
            User.email.isnot(None)
        ).all()
        return [
            (admin.username, admin.email, admin.full_name or admin.username)
            for admin in admin_users
            if admin.email
        ]
    except Exception as e:
        logger.error(f"Error getting admin users for notification: {e}", exc_info=True)
        return None
    finally:
        db.close()


def send_notification_to_all_admins(
    subject_template: str,
    body_text_template: str,
    body_html_template: str,
    notification_type: str = "notification",
    template_vars: dict = None,
) -> bool:
    """
    Send an email notification to all active admin users using their individual language preferences.

    Args:
        subject_template: Email subject template (will be rendered with each admin's language)
        body_text_template: Plain text body template (will be rendered with each admin's language)
        body_html_template: HTML body template (will be rendered with each admin's language)
        notification_type: Type of notification (for logging purposes)
        template_vars: Additional template variables to pass to the renderer

    Returns:
        True if at least one email was accepted by the outbound queue, False otherwise.
        Delivery happens on a mail worker afterwards, so this is not a delivery receipt —
        no caller ever treated it as one.
    """
    if not _email_is_configured(notification_type):
        return False

    recipients = _load_admin_recipients()
    if recipients is None:
        return False
    if not recipients:
        logger.warning(f"No active admin users with email addresses found for {notification_type}")
        return False

    logger.info(f"Sending {notification_type} to {len(recipients)} admin(s)")

    # Admin notifications go out in the server's default locale.
    admin_language = settings.BABEL_DEFAULT_LOCALE
    gettext = get_gettext(admin_language)

    success_count = 0
    for username, email, display_name in recipients:
        try:
            admin_template_vars = {
                "_": gettext,
                "admin_display_name": display_name,
                **(template_vars or {})
            }

            # Rendered per admin because the display name differs. The variables are
            # passed in rather than closed over: defining the renderer inside the loop
            # made it capture the dict by reference, so it rendered whatever the
            # variable held at call time — harmless while every call happened in the
            # same iteration, but the shape that silently sends every admin the last
            # admin's data as soon as one of these calls is deferred.
            subject = render_source(subject_template, admin_template_vars)
            body_text = render_source(body_text_template, admin_template_vars)
            body_html = render_source(body_html_template, admin_template_vars)

            # LOW priority: nobody is waiting on an admin report, and it must not be
            # able to crowd out a password-reset mail.
            if queue_email_notification(email, subject, body_text, body_html, Priority.LOW):
                success_count += 1
                logger.info(f"{notification_type.capitalize()} queued for admin: {username} (language: {admin_language})")
            else:
                logger.warning(f"Failed to queue {notification_type} for admin: {username}")
        except Exception as e:
            logger.error(f"Error preparing {notification_type} for {username}: {e}")

    if success_count > 0:
        logger.info(f"{notification_type.capitalize()} queued for {success_count}/{len(recipients)} admin(s)")
        return True

    logger.error(f"Failed to queue {notification_type} for any admin")
    return False


def send_admin_security_notification(subject_template: str, body_text_template: str, body_html_template: str, template_vars: dict = None) -> bool:
    """
    Send a security notification email to all active admin users using their individual language preferences.
    This is a convenience wrapper around send_notification_to_all_admins().
    """
    return send_notification_to_all_admins(subject_template, body_text_template, body_html_template, "security notification", template_vars)


def send_new_user_admin_notification(new_user: "User"):
    """
    Sends an email notification to all active admins about a new user registration.
    Each admin receives the notification in their preferred language.
    """
    if not _email_is_configured("new user registration notification"):
        return

    try:
        subject_template = "📢 {{ _('New User Registration on PyOVMS') }}: {{ new_user_username }}"
        user_management_url = f"{settings.SERVER_BASE_URL.rstrip('/')}/users"

        template_vars = {
            "new_user_username": new_user.username,
            "new_user_email": new_user.email,
            "registration_time": as_utc(new_user.created_at).strftime('%Y-%m-%d %H:%M:%S UTC'),
            "user_management_url": user_management_url,
            "server_base_url": settings.SERVER_BASE_URL
        }

        send_notification_to_all_admins(
            subject_template,
            "email/admin_new_user_notification.txt",
            "email/admin_new_user_notification.html",
            "new user registration notification",
            template_vars
        )
    except Exception as e:
        logger.error(f"Error preparing new user admin notification: {e}", exc_info=True)


# Jinja placeholders, not %-substitution. These strings are compiled and cached as
# templates by render_source(); interpolating the vehicle id or username *into* the
# source first made every event produce a template nothing else would ever match, and
# put a stored, user-supplied value where template syntax is read. Both are validated
# to alphanumerics elsewhere, so this closes the shape rather than a live hole.
_LIFECYCLE_SUBJECTS = {
    "unused_vehicle_warning": "⚠️ [Lifecycle] Unused vehicle warning sent: {{ vehicle_id }}",
    "vehicle_auto_deleted": "🗑️ [Lifecycle] Vehicle auto-deleted: {{ vehicle_id }}",
    "account_deletion_warning": "⚠️ [Lifecycle] Account deletion warning sent: {{ username }}",
    "account_auto_deleted": "🗑️ [Lifecycle] Account auto-deleted: {{ username }}",
}


def send_lifecycle_admin_notification(event_type: str, template_vars: dict) -> bool:
    """
    Send a lifecycle event notification to all admins.
    event_type: 'unused_vehicle_warning', 'vehicle_auto_deleted', 'account_deletion_warning', 'account_auto_deleted'
    """
    # An unknown event_type is not interpolated into the subject: it would be a template
    # source built from a caller-supplied string, which is exactly what the table above
    # avoids.
    subject_tmpl = _LIFECYCLE_SUBJECTS.get(event_type, "[Lifecycle] {{ event_type }}")

    if event_type in ("unused_vehicle_warning", "vehicle_auto_deleted"):
        text_tmpl = "email/admin_lifecycle_vehicle.txt"
        html_tmpl = "email/admin_lifecycle_vehicle.html"
    else:
        text_tmpl = "email/admin_lifecycle_account.txt"
        html_tmpl = "email/admin_lifecycle_account.html"

    vars_with_event = {"event_type": event_type, **template_vars}
    return send_notification_to_all_admins(
        subject_tmpl, text_tmpl, html_tmpl, f"lifecycle ({event_type})", vars_with_event
    )
