"""SMTP delivery.

Named smtp rather than email so that `from email.mime.text import ...` below keeps
meaning the standard library.
"""

import logging
import smtplib
import ssl
from contextlib import contextmanager
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from app.config import settings
from app.utils.email_validation import (
    InvalidEmailAddress,
    sanitize_header_value,
    validate_email_address,
)

logger = logging.getLogger(__name__)

SMTP_TIMEOUT_SECONDS = 10


@contextmanager
def smtp_connection():
    """An authenticated SMTP connection, always closed.

    The old inline version called server.quit() only on the success path: any exception
    between connect and sendmail — an auth failure, a refused recipient, a timeout on a
    single message — leaked the socket, and with the retrying that sat on top of it that
    was up to three leaked connections per failing send.
    """
    # Without an explicit context both SMTP_SSL() and starttls() fall back to
    # ssl._create_stdlib_context(), which sets check_hostname=False and
    # verify_mode=CERT_NONE. Anyone on the path to the mail server could then
    # terminate TLS with any certificate and collect the SMTP login below plus
    # every password-reset and verification link we send.
    tls_context = ssl.create_default_context()
    if settings.EMAIL_USE_SSL:
        server = smtplib.SMTP_SSL(
            settings.EMAIL_HOST, settings.EMAIL_PORT, timeout=SMTP_TIMEOUT_SECONDS, context=tls_context
        )
    else:
        server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT, timeout=SMTP_TIMEOUT_SECONDS)
        if settings.EMAIL_USE_TLS:
            server.starttls(context=tls_context)

    try:
        if settings.EMAIL_USERNAME and settings.EMAIL_PASSWORD:
            server.login(settings.EMAIL_USERNAME, settings.EMAIL_PASSWORD)
        yield server
    finally:
        try:
            server.quit()
        except Exception:
            try:
                server.close()
            except Exception:
                pass


def deliver(server, recipient_email: str, subject: str, body_text: str,
            body_html: Optional[str] = None) -> None:
    """Send one message over an already-open connection.

    Raises on any failure — classification and retry belong to the caller. This is what
    the queue workers use, so that one authenticated connection carries several messages
    instead of one handshake per mail.
    """
    msg = build_message(recipient_email, subject, body_text, body_html)
    server.sendmail(settings.EMAIL_SENDER, [recipient_email], msg.as_string())


def build_message(recipient_email: str, subject: str, body_text: str, body_html: Optional[str] = None):
    if body_html:
        msg = MIMEMultipart('alternative')
        msg.attach(MIMEText(body_text, 'plain', 'utf-8'))
        msg.attach(MIMEText(body_html, 'html', 'utf-8'))
    else:
        msg = MIMEText(body_text, 'plain', 'utf-8')

    msg['Subject'] = subject
    msg['From'] = settings.EMAIL_SENDER
    msg['To'] = recipient_email
    return msg


def send_email_notification(recipient_email: str, subject: str, body_text: str, body_html: Optional[str] = None) -> bool:
    """Send one message synchronously, opening a connection for it. One attempt only.

    Not the normal path — everything in this repository goes through
    app.notifications.email_queue, which does not block the caller, reuses connections
    and retries for far longer. This exists for the case where the answer to "did it go
    out?" is needed before returning, and because it was public API before the queue.

    It does not retry, deliberately. It used to, by sleeping on the caller's thread for
    up to fifteen seconds — which is the one thing a function whose entire reason to
    exist is "answer synchronously" must not do. A caller that wants the message
    delivered rather than attempted wants queue_email_notification().
    """
    if not all([settings.EMAIL_HOST, settings.EMAIL_SENDER, recipient_email]):
        logger.warning("Email server settings (host, sender) or recipient email not configured. Skipping email notification.")
        return False

    # Last line of defence before SMTP. Recipients are user-supplied and subjects
    # are partly vehicle-supplied, so validate here rather than trusting that every
    # caller did — this also catches rows written before the field was validated.
    try:
        recipient_email = validate_email_address(recipient_email)
    except InvalidEmailAddress as e:
        logger.error(f"Refusing to send email: invalid recipient address ({e}). Skipping.")
        return False

    safe_subject = sanitize_header_value(subject)
    if safe_subject != subject:
        logger.warning("Email subject contained control characters; they were removed before sending.")
    subject = safe_subject

    msg = build_message(recipient_email, subject, body_text, body_html)

    try:
        with smtp_connection() as server:
            server.sendmail(settings.EMAIL_SENDER, [recipient_email], msg.as_string())
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"Failed to send email due to authentication error: {e}", exc_info=True)
        return False
    except smtplib.SMTPRecipientsRefused as e:
        logger.error(f"Mail server refused recipient: {e}")
        return False
    except Exception as e:
        # The decorator that used to sit here turned every failure into a bool; keeping
        # that contract matters more than the retrying did, because the callers of a
        # synchronous send branch on the answer rather than handling exceptions.
        logger.error(f"Failed to send email to {recipient_email}: {e}", exc_info=True)
        return False

    logger.info(f"Email notification sent to {recipient_email} with subject: '{subject}'")
    return True
