"""Retry policy for outbound notification sends.

"""

import logging
import random
import smtplib

import requests
# Imported as a submodule on purpose: `import firebase_admin` alone does not bind
# firebase_admin.exceptions, and the tuple below is built at import time.
from firebase_admin import exceptions as firebase_exceptions

from app.notifications.errors import TransientDeliveryError
from app.services.apns_client import ApnsTransientError

logger = logging.getLogger(__name__)

# Failures that a later attempt has a real chance of getting past.
TRANSIENT_EXCEPTIONS = (
    TransientDeliveryError,
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.ChunkedEncodingError,
    smtplib.SMTPServerDisconnected,
    smtplib.SMTPConnectError,
    smtplib.SMTPHeloError,
    smtplib.SMTPSenderRefused,
    TimeoutError,
    OSError,
    firebase_exceptions.UnavailableError,
    firebase_exceptions.InternalError,
    ApnsTransientError,
)

# Failures that will fail again identically, and must not be retried even though the
# tuple above appears to cover them.
#
# requests.RequestException derives from OSError, so the blanket `OSError` entry made
# *every* requests failure retryable — including a malformed URL or a redirect loop.
# Each of those then cost three attempts and 15 seconds of a worker thread to arrive at
# the answer it already had on the first one. OSError stays, because smtplib raises it
# raw for "network unreachable" during connect, which genuinely is worth retrying.
NON_RETRYABLE_EXCEPTIONS = (
    requests.exceptions.HTTPError,
    requests.exceptions.URLRequired,
    requests.exceptions.TooManyRedirects,
    requests.exceptions.MissingSchema,
    requests.exceptions.InvalidSchema,
    requests.exceptions.InvalidURL,
    requests.exceptions.InvalidHeader,
    smtplib.SMTPAuthenticationError,
    smtplib.SMTPNotSupportedError,
)

# The lowest SMTP reply code that means "permanent failure" (RFC 5321 §4.2.1: 4xx is a
# transient negative reply, 5xx a permanent one).
SMTP_PERMANENT_FAILURE_CODE = 500


def _smtp_is_permanent(exc: BaseException) -> bool:
    """Whether an smtplib failure carries a permanent (5xx) reply code.

    `smtplib.SMTPException` derives from OSError, so the blanket OSError entry above
    swept every SMTP failure into "transient" — including a 550 spam rejection or a
    552 message-too-large, each of which then burned the queue's full ~40-minute retry
    schedule, per recipient, to arrive at the answer it already had on the first try.

    The reply code is what decides, not the exception class: a 4xx is exactly the case
    retrying exists for (greylisting answers 450, and giving up on it would mean never
    delivering to a greylisting recipient at all).
    """
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        # Raised when *every* recipient was refused; the codes are per address.
        codes = [code for code, _msg in (exc.recipients or {}).values()]
        return bool(codes) and all(code >= SMTP_PERMANENT_FAILURE_CODE for code in codes)
    if isinstance(exc, smtplib.SMTPResponseException):
        return exc.smtp_code >= SMTP_PERMANENT_FAILURE_CODE
    return False


def is_transient(exc: BaseException) -> bool:
    """Whether `exc` is worth another attempt."""
    if isinstance(exc, NON_RETRYABLE_EXCEPTIONS):
        return False
    if _smtp_is_permanent(exc):
        return False
    return isinstance(exc, TRANSIENT_EXCEPTIONS)


# Backoff between push attempts, in seconds; one entry per retry, so a target is tried
# len() + 1 times in total. Longer than the old 5/10 s, and affordable precisely because
# no thread is held while it elapses — the whole schedule spans about a minute and a
# half, which is the outer limit of when a "charge complete" is still worth delivering.
PUSH_RETRY_DELAYS_SECONDS = (5.0, 20.0, 60.0)

# Up to this much is added on top, proportionally, at random.
#
# The jitter is not cosmetic: the dispatcher fans one notification out to every
# subscription of a vehicle at once, and a server's vehicles tend to fail against the
# same push host at the same moment. Without it every one of those retries comes back
# in lockstep on the same second, which is how a host that was briefly overloaded is
# kept overloaded.
RETRY_JITTER_FRACTION = 0.25

MAX_SEND_ATTEMPTS = len(PUSH_RETRY_DELAYS_SECONDS) + 1


def backoff_delay(attempt: int) -> float:
    """Seconds to wait before attempt `attempt` + 1, jittered.

    `attempt` is 1-based and counts attempts already made. Returns 0.0 once the budget
    is spent, which the caller reads as "give up" — see MAX_SEND_ATTEMPTS.
    """
    if attempt < 1 or attempt > len(PUSH_RETRY_DELAYS_SECONDS):
        return 0.0
    base = PUSH_RETRY_DELAYS_SECONDS[attempt - 1]
    return base * (1.0 + random.random() * RETRY_JITTER_FRACTION)
